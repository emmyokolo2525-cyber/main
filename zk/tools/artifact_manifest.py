#!/usr/bin/env python3
"""Reproducible-artifact manifest tool for the Harpocrates zk pipeline.

Guarantees that generated ACIR bundles, verification keys, and WASM artifacts
match their source and the pinned toolchain in ``zk/toolchain.lock.json``.

    write    normalize every declared artifact, digest it, and emit a manifest
    verify   re-digest the working tree and fail on any drift from a manifest
    compare  diff two manifests (the double-build reproducibility check)

State machine
-------------
Each artifact moves through exactly one terminal state per run::

    DECLARED ──not on disk──▶ MISSING      (fatal if `required`, else SKIPPED)
             ──over limit───▶ OVERSIZE     (fatal)
             ──unreadable───▶ UNREADABLE   (fatal)
             ──normalized───▶ DIGESTED     (success)

`verify` and `compare` add one more transition on a DIGESTED artifact:
``MATCHED`` or ``DRIFTED``. There is no partial success: a run that ends with
any fatal state exits non-zero and the manifest is not written, so a half-built
tree can never be promoted into a manifest.

Privacy
-------
Signals are structured JSON on stderr and carry only repo-relative paths,
byte counts, digests, and state names. Artifact *contents* — which for the
witness pipeline may be derived from private material — are never logged, never
echoed on failure, and never embedded in the manifest.

Determinism
-----------
Digests are taken over the *normalized* form defined by the lock file, so a
rebuild on a different host with the same pinned toolchain produces an
identical manifest. Normalization only removes fields the lock file names; it
can never mask a change to circuit semantics.

See docs/zk-reproducible-builds.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

MANIFEST_FORMAT = "harpocrates.zk-artifact-manifest"
MANIFEST_VERSION = 1

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = REPO_ROOT / "zk" / "toolchain.lock.json"
DEFAULT_MANIFEST = REPO_ROOT / "zk" / "artifacts.manifest.json"

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2
EXIT_FATAL = 3


class ArtifactState:
    """Terminal states an artifact can reach in a single run."""

    MISSING = "missing"
    SKIPPED = "skipped"
    OVERSIZE = "oversize"
    UNREADABLE = "unreadable"
    DIGESTED = "digested"
    MATCHED = "matched"
    DRIFTED = "drifted"


FATAL_STATES = frozenset({ArtifactState.OVERSIZE, ArtifactState.UNREADABLE})


class BuildError(RuntimeError):
    """Fatal, non-recoverable condition. Carries no artifact content."""


# ── Signals ─────────────────────────────────────────────────────────────────


def signal(event: str, **fields: Any) -> None:
    """Emit one privacy-safe structured signal on stderr.

    Only repo-relative paths, sizes, digests, counts, and state names are
    permitted. Callers must never pass artifact bytes.
    """
    payload = {"event": event, **fields}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)


# ── Lock file ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Limits:
    max_artifact_bytes: int
    max_artifacts: int
    max_provenance_files: int


@dataclass(frozen=True)
class Lock:
    raw: dict
    limits: Limits
    volatile_json_keys: frozenset[str]
    strip_custom_sections: frozenset[str]
    artifacts: tuple[dict, ...]
    provenance_globs: tuple[str, ...]

    @property
    def toolchain(self) -> dict:
        return self.raw["toolchain"]

    @property
    def environment(self) -> dict:
        return self.raw["environment"]


def load_lock(path: Path) -> Lock:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BuildError(f"toolchain lock not found: {_rel(path)}") from exc
    except json.JSONDecodeError as exc:
        raise BuildError(f"toolchain lock is not valid JSON: {_rel(path)}") from exc

    if raw.get("format") != "harpocrates.zk-toolchain-lock":
        raise BuildError("toolchain lock has an unexpected format identifier")
    if raw.get("version") != 1:
        raise BuildError(f"unsupported toolchain lock version: {raw.get('version')!r}")

    limits_raw = raw["limits"]
    limits = Limits(
        max_artifact_bytes=int(limits_raw["max_artifact_bytes"]),
        max_artifacts=int(limits_raw["max_artifacts"]),
        max_provenance_files=int(limits_raw["max_provenance_files"]),
    )

    artifacts = tuple(raw["artifacts"])
    if len(artifacts) > limits.max_artifacts:
        raise BuildError(
            f"lock declares {len(artifacts)} artifacts, above the cap of {limits.max_artifacts}"
        )

    return Lock(
        raw=raw,
        limits=limits,
        volatile_json_keys=frozenset(raw["normalization"]["json"]["volatile_keys"]),
        strip_custom_sections=frozenset(
            raw["normalization"]["wasm"]["strip_custom_sections"]
        ),
        artifacts=artifacts,
        provenance_globs=tuple(raw["provenance_sources"]["globs"]),
    )


# ── Normalization ───────────────────────────────────────────────────────────


def strip_volatile(value: Any, volatile_keys: frozenset[str]) -> Any:
    """Recursively drop keys the lock file declares volatile."""
    if isinstance(value, dict):
        return {
            key: strip_volatile(item, volatile_keys)
            for key, item in value.items()
            if key not in volatile_keys
        }
    if isinstance(value, list):
        return [strip_volatile(item, volatile_keys) for item in value]
    return value


def normalize_json(data: bytes, volatile_keys: frozenset[str]) -> bytes:
    """Canonicalize a JSON artifact: volatile keys removed, keys sorted, no
    incidental whitespace."""
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuildError("artifact declared as JSON is not valid UTF-8 JSON") from exc

    return json.dumps(
        strip_volatile(parsed, volatile_keys),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a LEB128 unsigned integer. Bounded to five bytes (u32)."""
    result = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            raise BuildError("truncated WASM: LEB128 ran past end of file")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
    raise BuildError("malformed WASM: over-long LEB128")


def normalize_wasm(data: bytes, strip_sections: frozenset[str]) -> bytes:
    """Drop the custom sections named in the lock file, preserving everything
    else byte-for-byte and in order.

    Implemented as a bounded forward walk with no recursion, so a corrupted or
    hostile module fails fast rather than consuming unbounded resources.
    """
    if len(data) < 8 or data[:4] != b"\x00asm":
        raise BuildError("artifact declared as WASM lacks the \\0asm magic header")

    out = bytearray(data[:8])  # magic + version
    offset = 8

    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, after_size = _read_uleb128(data, offset)
        body_start = after_size
        body_end = body_start + size
        if body_end > len(data):
            raise BuildError("truncated WASM: section length exceeds file size")

        if section_id == 0:  # custom section
            name_len, name_start = _read_uleb128(data, body_start)
            name_end = name_start + name_len
            if name_end > body_end:
                raise BuildError("malformed WASM: custom section name exceeds section")
            name = data[name_start:name_end].decode("utf-8", errors="replace")
            if name in strip_sections:
                offset = body_end
                continue

        out += data[offset - 1 : body_end]
        offset = body_end

    return bytes(out)


def normalize(data: bytes, kind: str, lock: Lock) -> bytes:
    if kind == "json":
        return normalize_json(data, lock.volatile_json_keys)
    if kind == "wasm":
        return normalize_wasm(data, lock.strip_custom_sections)
    if kind == "binary":
        return data
    raise BuildError(f"unknown artifact kind in lock file: {kind!r}")


# ── Digesting ───────────────────────────────────────────────────────────────


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rel(path: Path) -> str:
    """Repo-relative, forward-slashed path — the only path form ever logged."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name


@dataclass
class ArtifactResult:
    path: str
    kind: str
    role: str
    state: str
    raw_bytes: int | None = None
    normalized_bytes: int | None = None
    raw_sha256: str | None = None
    normalized_sha256: str | None = None

    def to_entry(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "role": self.role,
            "raw_bytes": self.raw_bytes,
            "normalized_bytes": self.normalized_bytes,
            "raw_sha256": self.raw_sha256,
            "normalized_sha256": self.normalized_sha256,
        }


def digest_artifact(declaration: dict, lock: Lock, root: Path) -> ArtifactResult:
    relative = declaration["path"]
    kind = declaration["kind"]
    role = declaration.get("role", "unknown")
    required = bool(declaration.get("required", False))
    target = root / relative

    result = ArtifactResult(path=relative, kind=kind, role=role, state=ArtifactState.MISSING)

    if not target.is_file():
        result.state = ArtifactState.MISSING if required else ArtifactState.SKIPPED
        signal("artifact.state", path=relative, state=result.state, required=required)
        return result

    size = target.stat().st_size
    if size > lock.limits.max_artifact_bytes:
        result.state = ArtifactState.OVERSIZE
        result.raw_bytes = size
        signal(
            "artifact.state",
            path=relative,
            state=result.state,
            bytes=size,
            limit=lock.limits.max_artifact_bytes,
        )
        return result

    try:
        data = target.read_bytes()
    except OSError:
        result.state = ArtifactState.UNREADABLE
        signal("artifact.state", path=relative, state=result.state)
        return result

    normalized = normalize(data, kind, lock)

    result.state = ArtifactState.DIGESTED
    result.raw_bytes = len(data)
    result.normalized_bytes = len(normalized)
    result.raw_sha256 = sha256_hex(data)
    result.normalized_sha256 = sha256_hex(normalized)

    signal(
        "artifact.state",
        path=relative,
        state=result.state,
        bytes=result.raw_bytes,
        normalized_bytes=result.normalized_bytes,
        digest=result.normalized_sha256,
    )
    return result


# ── Provenance ──────────────────────────────────────────────────────────────


def collect_provenance(lock: Lock, root: Path) -> dict[str, str]:
    """Digest every source file that defines the artifacts.

    Sorted and bounded so the result is stable across filesystems with
    different directory iteration order.
    """
    found: dict[str, str] = {}
    for pattern in lock.provenance_globs:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            if len(found) >= lock.limits.max_provenance_files:
                raise BuildError(
                    f"provenance set exceeds {lock.limits.max_provenance_files} files"
                )
            found[_rel(path)] = sha256_hex(path.read_bytes())
    return dict(sorted(found.items()))


# ── Manifest ────────────────────────────────────────────────────────────────


@dataclass
class ManifestRun:
    entries: list[ArtifactResult] = field(default_factory=list)

    @property
    def fatal(self) -> list[ArtifactResult]:
        return [entry for entry in self.entries if entry.state in FATAL_STATES]

    @property
    def missing_required(self) -> list[ArtifactResult]:
        return [entry for entry in self.entries if entry.state == ArtifactState.MISSING]


def build_manifest(lock: Lock, root: Path) -> tuple[dict, ManifestRun]:
    run = ManifestRun()
    for declaration in lock.artifacts:
        run.entries.append(digest_artifact(declaration, lock, root))

    manifest = {
        "format": MANIFEST_FORMAT,
        "version": MANIFEST_VERSION,
        "toolchain": {
            "nargo": lock.toolchain["nargo"]["version"],
            "barretenberg": lock.toolchain["barretenberg"]["version"],
            "proving_scheme": lock.toolchain["proving_scheme"],
            "oracle_hash": lock.toolchain["oracle_hash"],
        },
        "environment": dict(sorted(lock.environment.items())),
        "normalization_policy_sha256": sha256_hex(
            json.dumps(lock.raw["normalization"], sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
        "provenance": collect_provenance(lock, root),
        "artifacts": [
            entry.to_entry()
            for entry in run.entries
            if entry.state == ArtifactState.DIGESTED
        ],
        "skipped": [
            entry.path
            for entry in run.entries
            if entry.state == ArtifactState.SKIPPED
        ],
    }
    return manifest, run


def serialize_manifest(manifest: dict) -> str:
    """Deterministic on-disk form: sorted keys, two-space indent, one trailing
    newline. Two builds that agree produce byte-identical files."""
    return json.dumps(manifest, sort_keys=True, indent=2) + "\n"


# ── Drift comparison ────────────────────────────────────────────────────────


def compare_manifests(expected: dict, actual: dict) -> list[str]:
    """Return a stable, human-readable list of drift findings.

    Findings name paths and digests only. A digest mismatch is reported as two
    digests, never as a content diff — dumping artifact bytes into CI logs is
    exactly the leak this pipeline exists to prevent.
    """
    findings: list[str] = []

    for key in ("format", "version"):
        if expected.get(key) != actual.get(key):
            findings.append(
                f"manifest {key}: expected {expected.get(key)!r}, got {actual.get(key)!r}"
            )

    for key, expected_value in sorted(expected.get("toolchain", {}).items()):
        actual_value = actual.get("toolchain", {}).get(key)
        if expected_value != actual_value:
            findings.append(
                f"toolchain.{key}: expected {expected_value!r}, got {actual_value!r}"
            )

    if expected.get("normalization_policy_sha256") != actual.get(
        "normalization_policy_sha256"
    ):
        findings.append(
            "normalization policy changed; artifacts digested under different rules"
        )

    expected_provenance = expected.get("provenance", {})
    actual_provenance = actual.get("provenance", {})
    for path in sorted(set(expected_provenance) | set(actual_provenance)):
        before = expected_provenance.get(path)
        after = actual_provenance.get(path)
        if before != after:
            findings.append(
                f"source {path}: {_short(before)} -> {_short(after)}"
            )

    expected_artifacts = {entry["path"]: entry for entry in expected.get("artifacts", [])}
    actual_artifacts = {entry["path"]: entry for entry in actual.get("artifacts", [])}

    for path in sorted(set(expected_artifacts) | set(actual_artifacts)):
        before = expected_artifacts.get(path)
        after = actual_artifacts.get(path)
        if before is None:
            findings.append(f"artifact {path}: unexpected, not present in the manifest")
            continue
        if after is None:
            findings.append(f"artifact {path}: missing from the rebuilt tree")
            continue
        if before.get("normalized_sha256") != after.get("normalized_sha256"):
            findings.append(
                f"artifact {path}: normalized digest "
                f"{_short(before.get('normalized_sha256'))} -> "
                f"{_short(after.get('normalized_sha256'))}"
            )
        elif before.get("raw_sha256") != after.get("raw_sha256"):
            findings.append(
                f"artifact {path}: raw bytes differ but normalize to the same digest "
                "(host metadata only; not a semantic change)"
            )

    return findings


def _short(digest: str | None) -> str:
    if digest is None:
        return "absent"
    return digest[:16]


# ── Commands ────────────────────────────────────────────────────────────────


def _fail_on_fatal(run: ManifestRun) -> None:
    for entry in run.fatal:
        signal("run.fatal", path=entry.path, state=entry.state)
    for entry in run.missing_required:
        signal("run.fatal", path=entry.path, state=entry.state)
    if run.fatal or run.missing_required:
        raise BuildError(
            f"{len(run.fatal) + len(run.missing_required)} artifact(s) in a fatal state; "
            "manifest not written"
        )


def command_write(args: argparse.Namespace) -> int:
    lock = load_lock(Path(args.lock))
    manifest, run = build_manifest(lock, REPO_ROOT)
    _fail_on_fatal(run)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialize_manifest(manifest), encoding="utf-8")

    signal(
        "manifest.written",
        path=_rel(output),
        artifacts=len(manifest["artifacts"]),
        skipped=len(manifest["skipped"]),
        sources=len(manifest["provenance"]),
    )
    return EXIT_OK


def command_verify(args: argparse.Namespace) -> int:
    lock = load_lock(Path(args.lock))
    expected = _load_manifest(Path(args.manifest))
    actual, run = build_manifest(lock, REPO_ROOT)
    _fail_on_fatal(run)

    findings = compare_manifests(expected, actual)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("verify.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("verify.ok", artifacts=len(actual["artifacts"]))
    return EXIT_OK


def _load_manifest(path: Path) -> dict:
    if not path.is_file():
        raise BuildError(f"manifest not found: {_rel(path)}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildError(f"manifest is not valid JSON: {_rel(path)}") from exc
    if manifest.get("format") != MANIFEST_FORMAT:
        raise BuildError(f"not an artifact manifest: {_rel(path)}")
    return manifest


def command_compare(args: argparse.Namespace) -> int:
    first = _load_manifest(Path(args.first))
    second = _load_manifest(Path(args.second))

    findings = compare_manifests(first, second)
    if findings:
        for finding in findings:
            signal("drift.finding", detail=finding)
        signal("compare.failed", findings=len(findings))
        return EXIT_DRIFT

    signal("compare.ok", artifacts=len(first.get("artifacts", [])))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--lock", default=str(DEFAULT_LOCK), help="path to zk/toolchain.lock.json"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    write = subparsers.add_parser("write", help="write a manifest from the working tree")
    write.add_argument("--output", default=str(DEFAULT_MANIFEST))
    write.set_defaults(handler=command_write)

    verify = subparsers.add_parser("verify", help="fail on drift from a manifest")
    verify.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    verify.set_defaults(handler=command_verify)

    compare = subparsers.add_parser("compare", help="diff two manifests (double build)")
    compare.add_argument("first")
    compare.add_argument("second")
    compare.set_defaults(handler=command_compare)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.handler(args))
    except BuildError as error:
        signal("run.error", reason=str(error))
        return EXIT_FATAL
    except KeyboardInterrupt:
        # Cancellation is a first-class outcome: nothing is half-written,
        # because the manifest is only written after every artifact resolves.
        signal("run.cancelled")
        return EXIT_FATAL


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    sys.exit(main())
