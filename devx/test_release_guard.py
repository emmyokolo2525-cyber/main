from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import release_guard


class ReleaseGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = release_guard.read_json(release_guard.DEFAULT_MANIFEST)

    def test_current_manifest_verifies(self) -> None:
        release_guard.verify(release_guard.DEFAULT_MANIFEST)

    def test_rejects_missing_component(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        del manifest["components"]["verifier"]
        with self.assertRaisesRegex(release_guard.ManifestError, "exactly"):
            release_guard.validate_manifest(manifest)

    def test_rejects_oversized_or_unpinned_artifact_path(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["artifacts"][0]["path"] = "../outside"
        with self.assertRaisesRegex(release_guard.ManifestError, "inside"):
            release_guard.validate_manifest(manifest)

    def test_rejects_digest_tampering(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["artifacts"][0]["sha256"] = "0" * 64
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as output:
            json.dump(manifest, output)
            output_path = Path(output.name)
        self.addCleanup(output_path.unlink)
        with self.assertRaisesRegex(release_guard.ManifestError, "digest mismatch"):
            release_guard.verify(output_path)

    def test_rejects_duplicate_artifact(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["artifacts"].append(copy.deepcopy(manifest["artifacts"][0]))
        with self.assertRaisesRegex(release_guard.ManifestError, "unique path"):
            release_guard.validate_manifest(manifest)

    def test_publication_rejects_non_active_rollout(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["rollout"]["state"] = "candidate"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as output:
            json.dump(manifest, output)
            output_path = Path(output.name)
        self.addCleanup(output_path.unlink)
        with self.assertRaisesRegex(release_guard.ManifestError, "rollout.state=active"):
            release_guard.verify(output_path, require_active=True)

    def test_active_release_requires_deployed_contract_artifacts(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["rollout"]["state"] = "active"
        manifest["rollout"]["approval"] = "change-123"
        with self.assertRaisesRegex(release_guard.ManifestError, "registry WASM"):
            release_guard.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
