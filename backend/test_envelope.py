import unittest
from datetime import datetime, timezone

from envelope import (
    MAGIC_V1,
    MAGIC_V2,
    pack_envelope,
    unpack_envelope,
    validate_v1,
    validate_v2,
    canonical_metadata_hash,
)


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.valid_v1 = {
            "protocol": "harpocrates",
            "version": 1,
            "tier": "silent",
            "sourceHash": "11" * 32,
            "proofId": "22" * 32,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.valid_v2 = self.valid_v1.copy()
        self.valid_v2["version"] = 2
        self.valid_v2["unknown_field"] = "should_be_preserved"

    def test_pack_unpack_v1(self):
        data = pack_envelope(self.valid_v1, version=1)
        self.assertTrue(data.startswith(MAGIC_V1))
        
        unpacked = unpack_envelope(data)
        self.assertEqual(unpacked, self.valid_v1)

    def test_pack_unpack_v2(self):
        data = pack_envelope(self.valid_v2, version=2)
        self.assertTrue(data.startswith(MAGIC_V2))
        
        unpacked = unpack_envelope(data)
        self.assertEqual(unpacked, self.valid_v2)

    def test_auto_migration_on_pack(self):
        # Packing a v1 dict as v2 should auto-upgrade version to 2
        data = pack_envelope(self.valid_v1, version=2)
        unpacked = unpack_envelope(data)
        self.assertEqual(unpacked["version"], 2)

    def test_validate_v1_rejects_missing_fields(self):
        invalid = self.valid_v1.copy()
        del invalid["proofId"]
        with self.assertRaises(ValueError):
            validate_v1(invalid)

    def test_validate_v2_preserves_unknown_fields(self):
        validated = validate_v2(self.valid_v2)
        self.assertEqual(validated["unknown_field"], "should_be_preserved")

    def test_canonical_hash_consistency(self):
        hash1 = canonical_metadata_hash(self.valid_v1)
        hash2 = canonical_metadata_hash(self.valid_v1.copy())
        self.assertEqual(hash1, hash2)


if __name__ == "__main__":
    unittest.main()
