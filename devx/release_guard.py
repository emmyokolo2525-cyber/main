#!/usr/bin/env python3
"""Fail-closed compatibility gate for a Harpocrates release bundle.

The manifest intentionally contains only public release identity and hashes.  It
must never contain witnesses, media, credentials, proofs, transaction blobs, or
private deployment credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "release" / "compatibility-manifest.json"
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
COMPONENTS = {"frontend", "backend", "circuit", "verifier", "registry"}
ROLLOUT_STATES = {"candidate", "staged", "active", "rollback"}
MAX_MANIFEST_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


class ManifestError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError("manifest exceeds the 256 KiB limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise ManifestError("manifest must be a JSON object")
    return value


def reject_unknown(value: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ManifestError(f"{location} has unknown fields: {', '.join(sorted(unknown))}")


def required_string(value: dict[str, Any], key: str, location: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ManifestError(f"{location}.{key} must be a non-empty string")
    return item


def validate_manifest(manifest: dict[str, Any]) -> None:
    reject_unknown(manifest, {"schema_version", "release_id", "protocol", "network", "rollout", "components", "artifacts", "compatibility"}, "manifest")
    if manifest.get("schema_version") != 1:
        raise ManifestError("manifest.schema_version must be 1")
    if required_string(manifest, "release_id", "manifest") != "harpocrates-1.0.0":
        raise ManifestError("manifest.release_id is not an approved release train")
    if manifest.get("protocol") != {"name": "harpocrates", "version": 1, "crypto_domain": "harpocrates:silent-witness:v1"}:
        raise ManifestError("manifest.protocol must use the approved versioned cryptographic domain")
    network = required_string(manifest, "network", "manifest")
    if network not in {"local", "testnet", "mainnet"}:
        raise ManifestError("manifest.network must be local, testnet, or mainnet")

    rollout = manifest.get("rollout")
    if not isinstance(rollout, dict):
        raise ManifestError("manifest.rollout must be an object")
    reject_unknown(rollout, {"state", "previous_release", "max_stage_percent", "approval"}, "manifest.rollout")
    if rollout.get("state") not in ROLLOUT_STATES:
        raise ManifestError("manifest.rollout.state is invalid")
    if not isinstance(rollout.get("max_stage_percent"), int) or not 0 <= rollout["max_stage_percent"] <= 100:
        raise ManifestError("manifest.rollout.max_stage_percent must be an integer from 0 to 100")
    if rollout["state"] in {"staged", "active"} and not required_string(rollout, "approval", "manifest.rollout"):
        raise ManifestError("staged and active releases require an approval reference")
    if rollout["state"] == "rollback" and not required_string(rollout, "previous_release", "manifest.rollout"):
        raise ManifestError("rollback requires previous_release")

    components = manifest.get("components")
    if not isinstance(components, dict) or set(components) != COMPONENTS:
        raise ManifestError("manifest.components must contain exactly frontend, backend, circuit, verifier, registry")
    for name, component in components.items():
        if not isinstance(component, dict):
            raise ManifestError(f"component {name} must be an object")
        reject_unknown(component, {"version", "api_version", "proof_system", "contract_interface_version"}, f"component {name}")
        if not SEMVER.fullmatch(required_string(component, "version", f"component {name}")):
            raise ManifestError(f"component {name}.version must be SemVer")
        if component.get("api_version") != 1:
            raise ManifestError(f"component {name}.api_version must be 1")
    if components["circuit"].get("proof_system") != "ultrahonk-v1" or components["verifier"].get("proof_system") != "ultrahonk-v1":
        raise ManifestError("circuit and verifier proof systems must both be ultrahonk-v1")
    if components["registry"].get("contract_interface_version") != 1 or components["frontend"].get("contract_interface_version") != 1:
        raise ManifestError("frontend and registry must both bind contract interface version 1")

    compatibility = manifest.get("compatibility")
    if compatibility != {"metadata_version": 1, "proof_public_inputs_version": 1, "migration": None}:
        raise ManifestError("manifest.compatibility must preserve the v1 metadata and proof interfaces or provide a versioned migration")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ManifestError("manifest.artifacts must be a non-empty array")
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ManifestError("every artifact must be an object")
        reject_unknown(artifact, {"component", "path", "sha256"}, "artifact")
        component = required_string(artifact, "component", "artifact")
        path = required_string(artifact, "path", "artifact")
        digest = required_string(artifact, "sha256", "artifact")
        if component not in COMPONENTS or path in seen or not HEX_256.fullmatch(digest):
            raise ManifestError("artifact component, unique path, or sha256 is invalid")
        candidate = (ROOT / path).resolve()
        if ROOT not in candidate.parents or candidate == ROOT:
            raise ManifestError("artifact path must stay inside the repository")
        seen.add(path)
    if {a["component"] for a in artifacts} != COMPONENTS:
        raise ManifestError("each component must contribute at least one artifact")
    if rollout["state"] == "active":
        registry_paths = {a["path"] for a in artifacts if a["component"] == "registry"}
        verifier_paths = {a["path"] for a in artifacts if a["component"] == "verifier"}
        if not any(path.endswith(".wasm") for path in registry_paths):
            raise ManifestError("active release requires a digest-pinned registry WASM artifact")
        if not any(path.endswith(".wasm") for path in verifier_paths) or not any(path.endswith(".vk") for path in verifier_paths):
            raise ManifestError("active release requires digest-pinned verifier WASM and VK artifacts")


def verify(manifest_path: Path, require_active: bool = False) -> None:
    manifest = read_json(manifest_path)
    validate_manifest(manifest)
    _verify_declared_component_versions(manifest)
    if require_active and manifest["rollout"]["state"] != "active":
        raise ManifestError("publication requires rollout.state=active")
    mismatches: list[str] = []
    for artifact in manifest["artifacts"]:
        path = ROOT / artifact["path"]
        if not path.is_file():
            mismatches.append(f"missing artifact: {artifact['path']}")
        elif path.stat().st_size > MAX_ARTIFACT_BYTES:
            mismatches.append(f"artifact exceeds 512 MiB limit: {artifact['path']}")
        elif sha256_file(path) != artifact["sha256"]:
            mismatches.append(f"digest mismatch: {artifact['path']}")
    if mismatches:
        raise ManifestError("; ".join(mismatches))


def _verify_declared_component_versions(manifest: dict[str, Any]) -> None:
    frontend = read_json(ROOT / "frontend" / "package.json")
    if frontend.get("version") != manifest["components"]["frontend"]["version"]:
        raise ManifestError("frontend package version does not match manifest")
    cargo = (ROOT / "contracts" / "contracts" / "harpocrates-registry" / "Cargo.toml").read_text(encoding="utf-8")
    registry_version = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.MULTILINE)
    if not registry_version or registry_version.group(1) != manifest["components"]["registry"]["version"]:
        raise ManifestError("registry Cargo version does not match manifest")


def main() -> int:
    parser = argparse.ArgumentParser(description="verify a Harpocrates compatibility release bundle")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--require-active", action="store_true")
    args = parser.parse_args()
    try:
        verify(args.manifest.resolve(), args.require_active)
    except ManifestError as exc:
        print(f"release gate failed: {exc}", file=sys.stderr)
        return 1
    print("release gate passed: compatibility manifest and artifact digests are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
