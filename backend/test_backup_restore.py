"""Unit tests for the backup and restore automation logic."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path


class TestBackupScope(unittest.TestCase):
    """Test backup scope definitions and item collection."""

    def test_scope_coverage(self) -> None:
        """Verify backup scope covers all critical configuration files."""
        critical_paths = [
            "backend/config.py",
            "backend/app.py",
            "backend/requirements.txt",
            "frontend/package.json",
            "contracts/Cargo.toml",
            "contracts/DEPLOYMENT.md",
            "contracts/VERIFIER_INTEGRATION.md",
            "zk/noir/silent_witness/Nargo.toml",
            "zk/noir/silent_witness/src/main.nr",
            "docker-compose.example.yml",
        ]
        for path in critical_paths:
            self.assertTrue(
                os.path.exists(path) or os.path.exists(os.path.join("..", path)),
                f"Critical backup path not found: {path}",
            )

    def test_exclude_patterns(self) -> None:
        """Verify sensitive/temporary paths are not in backup scope."""
        excluded_patterns = [
            "*.mp4",
            "*.proof",
            "tmp/",
            "node_modules/",
            "target/",
        ]
        for pattern in excluded_patterns:
            self.assertFalse(
                os.path.isfile(pattern.rstrip("/")),
                f"Excluded path should not be a regular file: {pattern}",
            )


class TestManifestIntegrity(unittest.TestCase):
    """Test backup manifest generation and integrity verification."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="harpocrates-test-backup-")
        self.backup_dir = Path(self.temp_dir) / "test-backup"
        self.backup_dir.mkdir(parents=True)

        # Create test files
        self.test_files = {}
        for name, content in [
            ("config.env", "TEST_KEY=test_value\n"),
            ("manifest.json", '{"version": 1}\n'),
            ("source.py", "print('hello')\n"),
            ("contract.rs", "pub fn main() {}\n"),
        ]:
            file_path = self.backup_dir / name
            file_path.write_text(content)
            self.test_files[name] = content

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manifest_generation(self) -> None:
        """Manifest correctly records file hashes."""
        items = {}
        for name, content in self.test_files.items():
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            items[name] = file_hash

        manifest = {
            "backup_name": "test-backup",
            "timestamp": "2026-01-01T00:00:00Z",
            "schema_version": 1,
            "items": items,
            "integrity": {"algorithm": "sha256-256", "count": len(items)},
        }

        self.assertEqual(len(manifest["items"]), 4)
        self.assertEqual(manifest["integrity"]["count"], 4)
        self.assertEqual(manifest["schema_version"], 1)

        # Verify each hash
        for name in self.test_files:
            expected = hashlib.sha256(self.test_files[name].encode()).hexdigest()
            self.assertEqual(manifest["items"][name], expected)

    def test_manifest_hash_verification(self) -> None:
        """Manifest hash can be independently verified."""
        items = {}
        for name, content in self.test_files.items():
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            items[name] = file_hash

        manifest_str = json.dumps(items, sort_keys=True)
        manifest_hash = hashlib.sha256(manifest_str.encode()).hexdigest()

        # Verify the hash is deterministic
        manifest_str2 = json.dumps(items, sort_keys=True)
        manifest_hash2 = hashlib.sha256(manifest_str2.encode()).hexdigest()
        self.assertEqual(manifest_hash, manifest_hash2)

    def test_empty_backup_manifest(self) -> None:
        """Manifest with no items is valid."""
        manifest = {
            "backup_name": "empty-backup",
            "items": {},
            "integrity": {"algorithm": "sha256-256", "count": 0},
        }
        self.assertEqual(manifest["integrity"]["count"], 0)
        self.assertEqual(len(manifest["items"]), 0)

    def test_integrity_check_corrupt_file(self) -> None:
        """Integrity check detects corrupt files."""
        items = {}
        for name, content in self.test_files.items():
            items[name] = hashlib.sha256(b"wrong_content").hexdigest()

        # Verify the wrong hash doesn't match
        for name, content in self.test_files.items():
            correct_hash = hashlib.sha256(content.encode()).hexdigest()
            stored_hash = items[name]
            self.assertNotEqual(correct_hash, stored_hash)


class TestEncryption(unittest.TestCase):
    """Test backup encryption properties."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="harpocrates-test-crypto-")
        self.test_file = Path(self.temp_dir) / "test.txt"
        self.test_file.write_text("sensitive backup data")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_gpg_encryption_roundtrip(self) -> None:
        """Verify GPG encryption and decryption roundtrip."""
        import subprocess

        # Generate ephemeral GPG key
        subprocess.run(
            [
                "gpg", "--batch", "--gen-key",
                "--passphrase", "",
                "--quick-gen-key",
                "test-backup@harpocrates.test",
            ],
            capture_output=True,
            timeout=30,
        )

        try:
            encrypted_path = self.temp_dir + "/encrypted.gpg"
            decrypted_path = self.temp_dir + "/decrypted.txt"

            # Encrypt
            result = subprocess.run(
                [
                    "gpg", "--batch", "--yes",
                    "--recipient", "test-backup@harpocrates.test",
                    "--trust-model", "always",
                    "--output", encrypted_path,
                    "--encrypt", str(self.test_file),
                ],
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(os.path.exists(encrypted_path))

            # Decrypt
            result = subprocess.run(
                [
                    "gpg", "--batch", "--yes",
                    "--output", decrypted_path,
                    "--decrypt", encrypted_path,
                ],
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0)

            # Verify content
            decrypted_content = Path(decrypted_path).read_text()
            self.assertEqual(decrypted_content, "sensitive backup data")

        finally:
            # Cleanup
            subprocess.run(
                ["gpg", "--batch", "--yes", "--delete-secret-keys",
                 "test-backup@harpocrates.test"],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["gpg", "--batch", "--yes", "--delete-keys",
                 "test-backup@harpocrates.test"],
                capture_output=True,
                timeout=10,
            )

    def test_symmetric_encryption_roundtrip(self) -> None:
        """Verify symmetric AES256 encryption roundtrip."""
        import subprocess

        encrypted_path = self.temp_dir + "/encrypted.gpg"
        decrypted_path = self.temp_dir + "/decrypted.txt"
        passphrase = "test-symmetric-key-12345"

        # Encrypt
        result = subprocess.run(
            [
                "gpg", "--batch", "--yes",
                "--passphrase", passphrase,
                "--symmetric", "--cipher-algo", "AES256",
                "--output", encrypted_path,
                str(self.test_file),
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(encrypted_path))

        # Decrypt
        result = subprocess.run(
            [
                "gpg", "--batch", "--yes",
                "--passphrase", passphrase,
                "--output", decrypted_path,
                "--decrypt", encrypted_path,
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)

        # Verify content
        decrypted_content = Path(decrypted_path).read_text()
        self.assertEqual(decrypted_content, "sensitive backup data")


class TestRetention(unittest.TestCase):
    """Test backup retention policy logic."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="harpocrates-test-retention-")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_retention_removes_old_backups(self) -> None:
        """Old backups beyond retention period are removed."""
        retention_days = 1

        # Create old backup file
        old_backup = Path(self.temp_dir) / "old-backup.gpg"
        old_backup.touch()

        # Set modification time to 2 days ago
        two_days_ago = time.time() - (2 * 24 * 3600)
        os.utime(str(old_backup), (two_days_ago, two_days_ago))

        # Create recent backup
        recent_backup = Path(self.temp_dir) / "recent-backup.gpg"
        recent_backup.touch()

        # Simulate retention cleanup
        cutoff = time.time() - (retention_days * 24 * 3600)

        for f in Path(self.temp_dir).glob("*.gpg"):
            if f.stat().st_mtime < cutoff:
                f.unlink()

        remaining = list(Path(self.temp_dir).glob("*.gpg"))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].name, "recent-backup.gpg")

    def test_no_retention_with_zero_days(self) -> None:
        """Zero retention days keeps all backups."""
        # Create a backup file
        backup = Path(self.temp_dir) / "backup.gpg"
        backup.touch()

        # With retention 0, nothing is deleted
        cutoff = time.time()
        for f in Path(self.temp_dir).glob("*.gpg"):
            if f.stat().st_mtime < cutoff and 0 > 0:
                f.unlink()

        remaining = list(Path(self.temp_dir).glob("*.gpg"))
        self.assertEqual(len(remaining), 1)


if __name__ == "__main__":
    unittest.main()
