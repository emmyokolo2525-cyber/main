#!/usr/bin/env bash
# =============================================================================
# Build Silent Witness Aggregator circuit
#
# Compiles the aggregation circuit, executes the witness, and generates a
# proof and verification key using the UltraHonk proving scheme.
#
# Usage:
#   ./zk/noir/scripts/build-silent-witness-aggregator.sh
#
# Prerequisites: nargo (Noir 1.0.0-beta.9+) and bb (Barretenberg 0.87.0+).
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/../silent_witness_aggregator"

echo "==> Compiling silent_witness_aggregator circuit..."
nargo check

echo "==> Executing witness..."
nargo execute witness

echo "==> Proving with UltraHonk..."
bb prove \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path ./target/silent_witness_aggregator.json \
  --witness_path ./target/witness.gz \
  --output_path ./target \
  --output_format bytes_and_fields

echo "==> Writing verification key..."
bb write_vk \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path ./target/silent_witness_aggregator.json \
  --output_path ./target \
  --output_format bytes_and_fields

# Normalize vk output directory structure (bb may create a subdirectory)
if [[ -d target/vk_fields.json && -f target/vk_fields.json/vk_fields.json ]]; then
  mv target/vk_fields.json/vk_fields.json target/vk_fields.json.tmp
  rmdir target/vk_fields.json
  mv target/vk_fields.json.tmp target/vk_fields.json
fi

if [[ -d target/vk && -f target/vk/vk ]]; then
  mv target/vk/vk target/vk.tmp
  rmdir target/vk
  mv target/vk.tmp target/vk
fi

echo "==> Verifying proof locally..."
bb verify \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --vk_path ./target/vk \
  --proof_path ./target/proof \
  --public_inputs_path ./target/public_inputs

echo "==> Aggregator circuit built and verified successfully."
