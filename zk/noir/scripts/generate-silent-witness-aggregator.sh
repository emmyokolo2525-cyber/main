#!/usr/bin/env bash
# =============================================================================
# Generate Silent Witness Aggregator Proof
#
# Generates an aggregated proof for multiple video hashes under a single
# credential identity.  Uses the aggregator helper circuit to derive batch
# public inputs (credential roots and nullifiers).
#
# Usage:
#   ./zk/noir/scripts/generate-silent-witness-aggregator.sh \
#     <video-hash-hex-0> <video-hash-hex-1> ... \
#     <credential-secret-field> <nullifier-secret-field> [output-dir]
#
# Arguments:
#   video-hash-hex-N  32-byte hex string for each video (up to 8)
#   credential-secret-field  Decimal field element
#   nullifier-secret-field   Decimal field element
#   output-dir               Optional output directory (default: generated/)
#
# Example:
#   ./zk/noir/scripts/generate-silent-witness-aggregator.sh \
#     aaaa...bbbb cccc...dddd \
#     12345 67890
# =============================================================================
set -euo pipefail

if [[ "$#" -lt 4 ]]; then
  echo "usage: $0 <video-hash-hex-0> [<video-hash-hex-1> ... <video-hash-hex-7>] <credential-secret-field> <nullifier-secret-field> [output-dir]" >&2
  exit 2
fi

# Parse arguments – last two positional args are secrets, optional last is output-dir
SCRIPT_ARGS=("$@")
TOTAL_ARGS="$#"
CREDENTIAL_SECRET="${SCRIPT_ARGS[$((TOTAL_ARGS - 2))]}"
NULLIFIER_SECRET="${SCRIPT_ARGS[$((TOTAL_ARGS - 1))]}"

# Check if the last argument looks like an output directory (non-hex, non-numeric)
LAST_ARG="${SCRIPT_ARGS[$((TOTAL_ARGS - 1))]}"
SECOND_LAST="${SCRIPT_ARGS[$((TOTAL_ARGS - 2))]}"

if [[ "$SECOND_LAST" =~ ^[0-9]+$ ]] && [[ "$LAST_ARG" =~ ^[0-9]+$ ]]; then
  # No output-dir provided
  BATCH_COUNT=$((TOTAL_ARGS - 2))
  OUTPUT_DIR=""
elif [[ "$SECOND_LAST" =~ ^[0-9]+$ ]]; then
  # Last arg is output-dir
  BATCH_COUNT=$((TOTAL_ARGS - 3))
  OUTPUT_DIR="$LAST_ARG"
else
  echo "error: invalid arguments. Provide field decimal secrets." >&2
  exit 2
fi

if [[ "$BATCH_COUNT" -lt 1 || "$BATCH_COUNT" -gt 8 ]]; then
  echo "error: batch size must be between 1 and 8 (got $BATCH_COUNT)" >&2
  exit 2
fi

echo "==> Batch size: $BATCH_COUNT"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HELPER_DIR="$ROOT_DIR/silent_witness_aggregator_helper"
CIRCUIT_DIR="$ROOT_DIR/silent_witness_aggregator"
HELPER_TOML="$HELPER_DIR/Prover.toml"
CIRCUIT_TOML="$CIRCUIT_DIR/Prover.toml"
HELPER_BACKUP="$HELPER_DIR/Prover.toml.harpocrates.bak"
CIRCUIT_BACKUP="$CIRCUIT_DIR/Prover.toml.harpocrates.bak"

cleanup() {
  if [[ -f "$HELPER_BACKUP" ]]; then
    mv "$HELPER_BACKUP" "$HELPER_TOML"
  fi
  if [[ -f "$CIRCUIT_BACKUP" ]]; then
    mv "$CIRCUIT_BACKUP" "$CIRCUIT_TOML"
  fi
}
trap cleanup EXIT

cp "$HELPER_TOML" "$HELPER_BACKUP" 2>/dev/null || true
cp "$CIRCUIT_TOML" "$CIRCUIT_BACKUP" 2>/dev/null || true

# Build Prover.toml for the aggregator helper
cat > "$HELPER_TOML" <<EOF
credential_secret = "$CREDENTIAL_SECRET"
nullifier_secret = "$NULLIFIER_SECRET"
EOF

for (( i=0; i<BATCH_COUNT; i++ )); do
  VIDEO_HASH="${SCRIPT_ARGS[$i]}"
  if [[ ! "$VIDEO_HASH" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "error: video hash $i must be a 32-byte hex string" >&2
    exit 2
  fi
  HI_HEX="${VIDEO_HASH:0:32}"
  LO_HEX="${VIDEO_HASH:32:32}"
  HI_DEC="$(python3 - "$HI_HEX" <<'PY'
import sys
print(int(sys.argv[1], 16))
PY
)"
  LO_DEC="$(python3 - "$LO_HEX" <<'PY'
import sys
print(int(sys.argv[1], 16))
PY
)"
  cat >> "$HELPER_TOML" <<EOF
video_hash_hi_${i} = "$HI_DEC"
video_hash_lo_${i} = "$LO_DEC"
EOF
done

# Pad remaining slots with zeros
for (( i=BATCH_COUNT; i<8; i++ )); do
  cat >> "$HELPER_TOML" <<EOF
video_hash_hi_${i} = "0"
video_hash_lo_${i} = "0"
EOF
done

echo "==> Running aggregator helper circuit..."
pushd "$HELPER_DIR" >/dev/null
HELPER_OUTPUT="$(nargo execute generated_helper)"
popd >/dev/null

echo "==> Parsing helper output..."
ROOTS_AND_NULLIFIERS="$(HELPER_OUTPUT="$HELPER_OUTPUT" python3 -c "
import os, re
mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# Extract all Field values
values = [int(m) % mod for m in re.findall(r'Field\((-?\d+)\)', os.environ['HELPER_OUTPUT'])]
# Each batch element returns (credential_root, nullifier) = 2 fields per element
assert len(values) == 16, f'Expected 16 field values, got {len(values)}'
print(' '.join(f'0x{value:064x}' for value in values))
")"
read -ra PAIRS <<< "$ROOTS_AND_NULLIFIERS"

# Build Prover.toml for the aggregator circuit
cat > "$CIRCUIT_TOML" <<EOF
credential_secret = "$CREDENTIAL_SECRET"
nullifier_secret = "$NULLIFIER_SECRET"
EOF

for (( i=0; i<8; i++ )); do
  CR_ROOT="${PAIRS[$((i * 2))]}"
  NULLIFIER="${PAIRS[$((i * 2 + 1))]}"

  if [[ "$i" -lt "$BATCH_COUNT" ]]; then
    VIDEO_HASH="${SCRIPT_ARGS[$i]}"
    HI_HEX="${VIDEO_HASH:0:32}"
    LO_HEX="${VIDEO_HASH:32:32}"
    HI_DEC="$(python3 - "$HI_HEX" <<<"print(int(sys.argv[1], 16))")"
    LO_DEC="$(python3 - "$LO_HEX" <<<"print(int(sys.argv[1], 16))")"
  else
    HI_DEC="0"
    LO_DEC="0"
  fi

  cat >> "$CIRCUIT_TOML" <<EOF
video_hash_hi_${i} = "$HI_DEC"
video_hash_lo_${i} = "$LO_DEC"
credential_root_${i} = "$CR_ROOT"
nullifier_${i} = "$NULLIFIER"
EOF
done

echo "==> Proving with aggregator circuit..."
pushd "$CIRCUIT_DIR" >/dev/null
nargo check >/dev/null
nargo execute witness >/dev/null
bb prove \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path ./target/silent_witness_aggregator.json \
  --witness_path ./target/witness.gz \
  --output_path ./target \
  --output_format bytes_and_fields >/dev/null
bb verify \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --vk_path ./target/vk \
  --proof_path ./target/proof \
  --public_inputs_path ./target/public_inputs >/dev/null
popd >/dev/null

# Generate unique output directory with batch ID
BATCH_ID="$(echo -n "${SCRIPT_ARGS[@]}" | sha256sum | head -c 64)"
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$CIRCUIT_DIR/target/generated/batch-$BATCH_ID"
fi
mkdir -p "$OUTPUT_DIR"

cp "$CIRCUIT_DIR/target/proof" "$OUTPUT_DIR/proof"
cp "$CIRCUIT_DIR/target/public_inputs" "$OUTPUT_DIR/public_inputs"

# Generate JSON manifest
python3 - "$BATCH_COUNT" "$BATCH_ID" "$CREDENTIAL_SECRET" "$OUTPUT_DIR" "${SCRIPT_ARGS[@]:0:BATCH_COUNT}" <<'PY'
import json
import pathlib
import sys

batch_count = int(sys.argv[1])
batch_id = sys.argv[2]
credential_secret = sys.argv[3]
output_dir = sys.argv[4]
video_hashes = sys.argv[5:5 + batch_count]

output = pathlib.Path(output_dir)
proof = output.joinpath("proof").read_bytes()
public_inputs = output.joinpath("public_inputs").read_bytes()

print(json.dumps({
    "protocol": "harpocrates",
    "version": 1,
    "type": "aggregated_batch",
    "batchId": batch_id,
    "batchSize": batch_count,
    "maxBatchSize": 8,
    "videoHashes": [vh.lower() for vh in video_hashes],
    "proof": proof.hex(),
    "publicInputs": public_inputs.hex(),
    "proofBytes": len(proof),
    "publicInputBytes": len(public_inputs),
    "proofPath": str(output.joinpath("proof")),
    "publicInputsPath": str(output.joinpath("public_inputs")),
}))
PY

echo "==> Aggregated proof generated successfully in $OUTPUT_DIR"
