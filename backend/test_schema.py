from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from schema import (
    discover_schemas,
    resolve_schema,
    validate_selective_disclosure_input,
)


def _write_schema(dir_path: Path, filename: str, data: dict) -> Path:
    path = dir_path / filename
    path.write_text(json.dumps(data))
    return path


class TestDiscoverSchemas(unittest.TestCase):
    def test_returns_empty_list_when_directory_missing(self):
        with patch("schema._SCHEMA_DIR", Path("/nonexistent")):
            self.assertEqual(discover_schemas(), [])

    def test_returns_empty_list_when_no_json_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("schema._SCHEMA_DIR", Path(tmp)):
                self.assertEqual(discover_schemas(), [])

    def test_discovers_valid_json_schemas(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp)
            _write_schema(dir_path, "age.json", {
                "schemaHash": "aa" * 32,
                "issuerNamespace": "bb" * 32,
                "version": 1,
                "attributeCount": 2,
                "active": True,
            })
            _write_schema(dir_path, "country.json", {
                "schemaHash": "cc" * 32,
                "issuerNamespace": "dd" * 32,
                "version": 1,
                "attributeCount": 1,
                "active": True,
            })
            with patch("schema._SCHEMA_DIR", dir_path):
                result = discover_schemas()
                self.assertEqual(len(result), 2)
                hashes = [s["schemaHash"] for s in result]
                self.assertIn("aa" * 32, hashes)
                self.assertIn("cc" * 32, hashes)

    def test_skips_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp)
            (dir_path / "bad.json").write_text("not json")
            (dir_path / "good.json").write_text(json.dumps({"schemaHash": "ee" * 32}))
            with patch("schema._SCHEMA_DIR", dir_path):
                result = discover_schemas()
                self.assertEqual(len(result), 1)

    def test_skips_non_dict_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp)
            _write_schema(dir_path, "arr.json", [1, 2, 3])
            with patch("schema._SCHEMA_DIR", dir_path):
                result = discover_schemas()
                self.assertEqual(len(result), 0)


class TestResolveSchema(unittest.TestCase):
    def test_returns_none_for_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("schema._SCHEMA_DIR", Path(tmp)):
                self.assertIsNone(resolve_schema("aa" * 32))

    def test_resolves_by_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp)
            _write_schema(dir_path, "test.json", {
                "schemaHash": "aa" * 32,
                "issuerNamespace": "bb" * 32,
                "version": 1,
            })
            with patch("schema._SCHEMA_DIR", dir_path):
                result = resolve_schema("aa" * 32)
                self.assertIsNotNone(result)
                self.assertEqual(result["schemaHash"], "aa" * 32)

    def test_returns_none_for_unknown_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp)
            _write_schema(dir_path, "test.json", {"schemaHash": "aa" * 32})
            with patch("schema._SCHEMA_DIR", dir_path):
                result = resolve_schema("ff" * 32)
                self.assertIsNone(result)

    def test_case_insensitive_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp)
            _write_schema(dir_path, "test.json", {"schemaHash": "AA" * 32})
            with patch("schema._SCHEMA_DIR", dir_path):
                result = resolve_schema("aa" * 32)
                self.assertIsNotNone(result)


class TestValidateSelectiveDisclosureInput(unittest.TestCase):
    def test_accepts_valid_input(self):
        body = {
            "schemaHash": "aa" * 32,
            "publicInputs": "00" * 352,
            "proof": "abcdef",
        }
        self.assertIsNone(validate_selective_disclosure_input(body))

    def test_rejects_missing_schema_hash(self):
        body = {"publicInputs": "00" * 352, "proof": "abcdef"}
        self.assertIsNotNone(validate_selective_disclosure_input(body))

    def test_rejects_missing_public_inputs(self):
        body = {"schemaHash": "aa" * 32, "proof": "abcdef"}
        self.assertIsNotNone(validate_selective_disclosure_input(body))

    def test_rejects_missing_proof(self):
        body = {"schemaHash": "aa" * 32, "publicInputs": "00" * 352}
        self.assertIsNotNone(validate_selective_disclosure_input(body))

    def test_rejects_malformed_schema_hash(self):
        body = {
            "schemaHash": "short",
            "publicInputs": "00" * 352,
            "proof": "abcdef",
        }
        self.assertIsNotNone(validate_selective_disclosure_input(body))

    def test_rejects_wrong_public_input_length(self):
        body = {
            "schemaHash": "aa" * 32,
            "publicInputs": "00" * 100,
            "proof": "abcdef",
        }
        self.assertIsNotNone(validate_selective_disclosure_input(body))

    def test_rejects_empty_proof(self):
        body = {
            "schemaHash": "aa" * 32,
            "publicInputs": "00" * 352,
            "proof": "",
        }
        self.assertIsNotNone(validate_selective_disclosure_input(body))

    def test_rejects_non_string_schema_hash(self):
        body = {
            "schemaHash": 12345,
            "publicInputs": "00" * 352,
            "proof": "abcdef",
        }
        self.assertIsNotNone(validate_selective_disclosure_input(body))


if __name__ == "__main__":
    unittest.main()
