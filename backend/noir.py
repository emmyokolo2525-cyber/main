from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[1]
SINGLE_SCRIPT_PATH = ROOT_DIR / "zk" / "noir" / "scripts" / "generate-silent-witness-wsl.ps1"
BATCH_SCRIPT_PATH = ROOT_DIR / "zk" / "noir" / "scripts" / "generate-silent-witness-aggregator.sh"


def generate_silent_witness(
    video_hash: str,
    credential_secret: str,
    nullifier_secret: str,
    verifier_scope: str = "0",
    epoch: int = 0,
) -> dict[str, Any]:
    """Generate a single Silent Witness proof."""
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SINGLE_SCRIPT_PATH),
            "-VideoHash",
            video_hash,
            "-CredentialSecret",
            credential_secret,
            "-NullifierSecret",
            nullifier_secret,
            "-VerifierScope",
            verifier_scope,
            "-Epoch",
            str(epoch),
        ],
        cwd=ROOT_DIR,
        check=False,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("NOIR_PROOF_TIMEOUT_SECONDS", "180")),
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or "Noir proof generation failed.")

    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)

    raise RuntimeError("Noir proof generator did not return JSON.")


def generate_aggregated_proof(
    video_hashes: list[str],
    credential_secret: str,
    nullifier_secret: str,
) -> dict[str, Any]:
    """Generate a bounded aggregated proof for multiple video hashes.

    Uses the Silent Witness Aggregator circuit to produce a single
    UltraHonk proof covering up to ``MAX_AGGREGATION_SIZE`` (8) video
    hashes under the same credential identity.

    Args:
        video_hashes: Ordered list of 32-byte hex video hashes (1-8).
        credential_secret: Decimal field string for the credential secret.
        nullifier_secret: Decimal field string for the nullifier secret.

    Returns:
        JSON-serialized dictionary with aggregated proof artifacts.

    Raises:
        ValueError: If the batch size is out of bounds.
        RuntimeError: If the Noir/batch process fails.
    """
    batch_size = len(video_hashes)
    if batch_size < 1 or batch_size > 8:
        raise ValueError(
            f"Batch size must be between 1 and 8 (got {batch_size})"
        )

    cmd = [
        "bash",
        str(BATCH_SCRIPT_PATH),
        *video_hashes,
        credential_secret,
        nullifier_secret,
    ]

    completed = subprocess.run(
        cmd,
        cwd=ROOT_DIR,
        check=False,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("NOIR_PROOF_TIMEOUT_SECONDS", "300")),
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or "Aggregated proof generation failed.")

    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)

    raise RuntimeError("Aggregated proof generator did not return JSON.")
