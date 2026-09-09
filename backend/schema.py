from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"


def discover_schemas() -> list[dict[str, Any]]:
    if not _SCHEMA_DIR.is_dir():
        return []
    schemas: list[dict[str, Any]] = []
    for path in sorted(_SCHEMA_DIR.glob("*.json")):
        try:
            with open(path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                continue
            schemas.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return schemas


def resolve_schema(schema_hash: str) -> dict[str, Any] | None:
    target = schema_hash.lower().strip()
    for schema in discover_schemas():
        candidate = schema.get("schemaHash", "").lower().strip()
        if candidate == target:
            return schema
    return None


def validate_selective_disclosure_input(
    body: dict[str, Any],
) -> str | None:
    required = {"schemaHash", "publicInputs", "proof"}
    missing = required - set(body.keys())
    if missing:
        return f"missing required field: {sorted(missing)[0]}"

    schema_hash = body.get("schemaHash", "")
    if not isinstance(schema_hash, str) or len(schema_hash) != 64:
        return "schemaHash must be a 64-char hex string"

    public_inputs = body.get("publicInputs", "")
    if not isinstance(public_inputs, str) or len(public_inputs) != 704:
        return "publicInputs must be a 704-char hex string (352 bytes)"

    proof = body.get("proof", "")
    if not isinstance(proof, str) or len(proof) < 2:
        return "proof must be a non-empty hex string"

    return None
