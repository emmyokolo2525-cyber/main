"""Unit tests for the reproducible-artifact manifest tool.

Covers the normalization rules, the bounded WASM walker, the artifact state
machine, drift detection, and the privacy property that no artifact content
ever reaches a signal, a manifest, or a drift finding.

Run from the repository root:

    python -m pytest zk/tools -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import artifact_manifest as am  # noqa: E402


LOCK_PATH = Path(__file__).resolve().parents[1] / "toolchain.lock.json"


@pytest.fixture()
def lock() -> am.Lock:
    return am.load_lock(LOCK_PATH)


# ── Lock file ───────────────────────────────────────────────────────────────


def test_repo_lock_loads_and_declares_required_artifacts(lock: am.Lock):
    assert lock.toolchain["nargo"]["version"]
    assert lock.toolchain["barretenberg"]["version"]
    assert any(entry.get("required") for entry in lock.artifacts)
    assert lock.limits.max_artifact_bytes > 0


def test_lock_rejects_unknown_version(tmp_path: Path):
    raw = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    raw["version"] = 99
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(am.BuildError, match="unsupported toolchain lock version"):
        am.load_lock(path)


def test_lock_rejects_foreign_format(tmp_path: Path):
    path = tmp_path / "lock.json"
    path.write_text(json.dumps({"format": "something-else", "version": 1}), encoding="utf-8")

    with pytest.raises(am.BuildError, match="unexpected format identifier"):
        am.load_lock(path)


def test_missing_lock_is_a_typed_failure(tmp_path: Path):
    with pytest.raises(am.BuildError, match="toolchain lock not found"):
        am.load_lock(tmp_path / "absent.json")


# ── JSON normalization ──────────────────────────────────────────────────────


def test_json_normalization_is_key_order_independent(lock: am.Lock):
    first = b'{"a":1,"b":{"c":2,"d":3}}'
    second = b'{"b":{"d":3,"c":2},"a":1}'

    assert am.normalize_json(first, lock.volatile_json_keys) == am.normalize_json(
        second, lock.volatile_json_keys
    )


def test_json_normalization_is_whitespace_independent(lock: am.Lock):
    compact = b'{"a":[1,2,3]}'
    spaced = b'{\n  "a": [\n    1,\n    2,\n    3\n  ]\n}\n'

    assert am.normalize_json(compact, lock.volatile_json_keys) == am.normalize_json(
        spaced, lock.volatile_json_keys
    )


def test_json_normalization_drops_declared_volatile_keys(lock: am.Lock):
    with_debug = json.dumps(
        {
            "bytecode": "AAA",
            "debug_symbols": "host-specific",
            "file_map": {"1": "/home/runner/work/x.nr"},
            "nested": {"names": ["main"], "keep": 1},
        }
    ).encode("utf-8")
    without_debug = json.dumps({"bytecode": "AAA", "nested": {"keep": 1}}).encode("utf-8")

    assert am.normalize_json(with_debug, lock.volatile_json_keys) == am.normalize_json(
        without_debug, lock.volatile_json_keys
    )


def test_json_normalization_still_detects_a_semantic_change(lock: am.Lock):
    """Normalization must never mask a real circuit change."""
    original = b'{"bytecode":"AAA","debug_symbols":"x"}'
    changed = b'{"bytecode":"AAB","debug_symbols":"x"}'

    assert am.normalize_json(original, lock.volatile_json_keys) != am.normalize_json(
        changed, lock.volatile_json_keys
    )


def test_json_normalization_rejects_non_json(lock: am.Lock):
    with pytest.raises(am.BuildError, match="not valid UTF-8 JSON"):
        am.normalize_json(b"\xff\xfe not json", lock.volatile_json_keys)


# ── WASM normalization ──────────────────────────────────────────────────────


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _custom_section(name: str, body: bytes = b"") -> bytes:
    encoded_name = name.encode("utf-8")
    payload = _uleb128(len(encoded_name)) + encoded_name + body
    return b"\x00" + _uleb128(len(payload)) + payload


def _typed_section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb128(len(body)) + body


WASM_HEADER = b"\x00asm\x01\x00\x00\x00"


def test_wasm_normalization_strips_declared_custom_sections(lock: am.Lock):
    keep = _typed_section(1, b"\x01\x02\x03")
    module = (
        WASM_HEADER
        + _custom_section("producers", b"clang-17")
        + keep
        + _custom_section("name", b"symbols")
    )

    assert am.normalize_wasm(module, lock.strip_custom_sections) == WASM_HEADER + keep


def test_wasm_normalization_preserves_unlisted_custom_sections(lock: am.Lock):
    kept_custom = _custom_section("harpocrates.provenance", b"v1")
    module = WASM_HEADER + kept_custom + _custom_section("producers", b"x")

    assert am.normalize_wasm(module, lock.strip_custom_sections) == WASM_HEADER + kept_custom


def test_wasm_normalization_preserves_section_order(lock: am.Lock):
    first = _typed_section(1, b"\xaa")
    second = _typed_section(3, b"\xbb")
    module = WASM_HEADER + first + _custom_section("producers") + second

    assert am.normalize_wasm(module, lock.strip_custom_sections) == WASM_HEADER + first + second


def test_wasm_normalization_is_idempotent(lock: am.Lock):
    module = WASM_HEADER + _custom_section("producers", b"x") + _typed_section(1, b"\x01")
    once = am.normalize_wasm(module, lock.strip_custom_sections)

    assert am.normalize_wasm(once, lock.strip_custom_sections) == once


@pytest.mark.parametrize(
    "module",
    [
        b"",
        b"\x00asm",
        b"notawasmmodule!!",
        b"\x00asm\x01\x00\x00",
    ],
)
def test_wasm_normalization_rejects_a_bad_header(module: bytes, lock: am.Lock):
    with pytest.raises(am.BuildError):
        am.normalize_wasm(module, lock.strip_custom_sections)


def test_wasm_normalization_rejects_a_truncated_section(lock: am.Lock):
    module = WASM_HEADER + b"\x01" + _uleb128(1000) + b"\x01\x02"

    with pytest.raises(am.BuildError, match="section length exceeds file size"):
        am.normalize_wasm(module, lock.strip_custom_sections)


def test_wasm_normalization_rejects_an_over_long_leb128(lock: am.Lock):
    module = WASM_HEADER + b"\x01" + b"\x80\x80\x80\x80\x80\x80"

    with pytest.raises(am.BuildError, match="over-long LEB128"):
        am.normalize_wasm(module, lock.strip_custom_sections)


def test_wasm_normalization_rejects_a_name_past_its_section(lock: am.Lock):
    payload = _uleb128(200) + b"short"
    module = WASM_HEADER + b"\x00" + _uleb128(len(payload)) + payload

    with pytest.raises(am.BuildError, match="custom section name exceeds section"):
        am.normalize_wasm(module, lock.strip_custom_sections)


# ── Artifact state machine ──────────────────────────────────────────────────


def _lock_for(tmp_path: Path, artifacts: list[dict], **overrides) -> am.Lock:
    raw = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    raw["artifacts"] = artifacts
    raw["limits"].update(overrides)
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return am.load_lock(path)


def test_optional_missing_artifact_is_skipped_not_fatal(tmp_path: Path):
    lock = _lock_for(tmp_path, [{"path": "absent.bin", "kind": "binary", "required": False}])
    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)

    assert result.state == am.ArtifactState.SKIPPED
    assert result.state not in am.FATAL_STATES


def test_required_missing_artifact_is_missing(tmp_path: Path):
    lock = _lock_for(tmp_path, [{"path": "absent.bin", "kind": "binary", "required": True}])
    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)

    assert result.state == am.ArtifactState.MISSING


def test_oversized_artifact_is_rejected_before_reading(tmp_path: Path):
    target = tmp_path / "big.bin"
    target.write_bytes(b"\x00" * 4096)
    lock = _lock_for(
        tmp_path,
        [{"path": "big.bin", "kind": "binary", "required": True}],
        max_artifact_bytes=16,
    )

    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)

    assert result.state == am.ArtifactState.OVERSIZE
    assert result.state in am.FATAL_STATES
    assert result.normalized_sha256 is None


def test_digested_artifact_records_both_digests(tmp_path: Path):
    target = tmp_path / "acir.json"
    target.write_text('{"b":2,"a":1,"debug_symbols":"host"}', encoding="utf-8")
    lock = _lock_for(tmp_path, [{"path": "acir.json", "kind": "json", "required": True}])

    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)

    assert result.state == am.ArtifactState.DIGESTED
    assert result.raw_sha256 != result.normalized_sha256
    assert len(result.normalized_sha256) == 64


def test_lock_rejects_more_artifacts_than_the_cap(tmp_path: Path):
    entries = [
        {"path": f"a{index}.bin", "kind": "binary", "required": False} for index in range(70)
    ]
    with pytest.raises(am.BuildError, match="above the cap"):
        _lock_for(tmp_path, entries)


def test_unknown_kind_is_a_typed_failure(tmp_path: Path, lock: am.Lock):
    with pytest.raises(am.BuildError, match="unknown artifact kind"):
        am.normalize(b"{}", "exotic", lock)


# ── Manifest and drift ──────────────────────────────────────────────────────


def _manifest(artifacts: list[dict], provenance: dict[str, str] | None = None) -> dict:
    return {
        "format": am.MANIFEST_FORMAT,
        "version": am.MANIFEST_VERSION,
        "toolchain": {"nargo": "1.0.0-beta.9", "barretenberg": "0.87.0"},
        "normalization_policy_sha256": "a" * 64,
        "provenance": provenance or {"zk/noir/silent_witness/src/main.nr": "b" * 64},
        "artifacts": artifacts,
        "skipped": [],
    }


def _artifact(path: str, normalized: str, raw: str | None = None) -> dict:
    return {
        "path": path,
        "kind": "json",
        "role": "acir",
        "raw_bytes": 10,
        "normalized_bytes": 8,
        "raw_sha256": raw or normalized,
        "normalized_sha256": normalized,
    }


def test_identical_manifests_report_no_drift():
    manifest = _manifest([_artifact("x.json", "c" * 64)])
    assert am.compare_manifests(manifest, manifest) == []


def test_changed_artifact_digest_is_reported():
    before = _manifest([_artifact("x.json", "c" * 64)])
    after = _manifest([_artifact("x.json", "d" * 64)])

    findings = am.compare_manifests(before, after)

    assert len(findings) == 1
    assert "x.json" in findings[0]
    assert "normalized digest" in findings[0]


def test_host_only_difference_is_reported_as_non_semantic():
    before = _manifest([_artifact("x.json", "c" * 64, raw="1" * 64)])
    after = _manifest([_artifact("x.json", "c" * 64, raw="2" * 64)])

    findings = am.compare_manifests(before, after)

    assert len(findings) == 1
    assert "not a semantic change" in findings[0]


def test_toolchain_drift_is_reported():
    before = _manifest([])
    after = _manifest([])
    after["toolchain"]["barretenberg"] = "0.88.0"

    findings = am.compare_manifests(before, after)

    assert any("toolchain.barretenberg" in finding for finding in findings)


def test_source_drift_is_reported():
    before = _manifest([], provenance={"zk/noir/silent_witness/src/main.nr": "b" * 64})
    after = _manifest([], provenance={"zk/noir/silent_witness/src/main.nr": "e" * 64})

    findings = am.compare_manifests(before, after)

    assert any("main.nr" in finding for finding in findings)


def test_added_and_removed_artifacts_are_both_reported():
    before = _manifest([_artifact("x.json", "c" * 64)])
    after = _manifest([_artifact("y.json", "c" * 64)])

    findings = am.compare_manifests(before, after)

    assert any("missing from the rebuilt tree" in finding for finding in findings)
    assert any("unexpected" in finding for finding in findings)


def test_normalization_policy_change_is_reported():
    before = _manifest([])
    after = _manifest([])
    after["normalization_policy_sha256"] = "f" * 64

    findings = am.compare_manifests(before, after)

    assert any("normalization policy changed" in finding for finding in findings)


def test_findings_are_deterministically_ordered():
    before = _manifest(
        [_artifact("b.json", "1" * 64), _artifact("a.json", "2" * 64)],
        provenance={"z.nr": "1" * 64, "a.nr": "2" * 64},
    )
    after = _manifest(
        [_artifact("b.json", "3" * 64), _artifact("a.json", "4" * 64)],
        provenance={"z.nr": "5" * 64, "a.nr": "6" * 64},
    )

    assert am.compare_manifests(before, after) == am.compare_manifests(before, after)


# ── Privacy ─────────────────────────────────────────────────────────────────


def test_drift_findings_never_contain_artifact_content():
    """A digest mismatch reports two digests, never the differing bytes."""
    secret = "WITNESS-MATERIAL-DO-NOT-LOG"
    before = _manifest([_artifact("x.json", "c" * 64)])
    after = _manifest([_artifact("x.json", "d" * 64)])

    rendered = " ".join(am.compare_manifests(before, after))

    assert secret not in rendered
    assert "c" * 64 not in rendered  # digests are truncated, not echoed in full


def test_manifest_never_embeds_artifact_bytes(tmp_path: Path):
    secret = b'{"bytecode":"SECRET-WITNESS-BYTES"}'
    target = tmp_path / "acir.json"
    target.write_bytes(secret)
    lock = _lock_for(tmp_path, [{"path": "acir.json", "kind": "json", "required": True}])

    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)
    rendered = json.dumps(result.to_entry())

    assert "SECRET-WITNESS-BYTES" not in rendered
    assert result.normalized_sha256 in rendered


def test_signals_are_single_line_json(capsys):
    am.signal("artifact.state", path="zk/noir/x.json", state="digested", bytes=10)
    captured = capsys.readouterr().err.strip()

    assert "\n" not in captured
    parsed = json.loads(captured)
    assert parsed["event"] == "artifact.state"
    assert set(parsed) == {"event", "path", "state", "bytes"}


# ── Serialization ───────────────────────────────────────────────────────────


def test_manifest_serialization_is_stable_and_newline_terminated():
    manifest = _manifest([_artifact("x.json", "c" * 64)])
    first = am.serialize_manifest(manifest)

    assert first.endswith("\n")
    assert first == am.serialize_manifest(json.loads(first))


def test_cli_rejects_an_unknown_command():
    with pytest.raises(SystemExit) as excinfo:
        am.main(["nonsense"])
    assert excinfo.value.code == am.EXIT_USAGE


def test_compare_command_exits_with_drift_code(tmp_path: Path):
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    first.write_text(am.serialize_manifest(_manifest([_artifact("x.json", "c" * 64)])))
    second.write_text(am.serialize_manifest(_manifest([_artifact("x.json", "d" * 64)])))

    assert am.main(["compare", str(first), str(second)]) == am.EXIT_DRIFT
    assert am.main(["compare", str(first), str(first)]) == am.EXIT_OK


def test_verify_reports_a_missing_manifest_as_fatal(tmp_path: Path):
    assert am.main(["verify", "--manifest", str(tmp_path / "absent.json")]) == am.EXIT_FATAL
