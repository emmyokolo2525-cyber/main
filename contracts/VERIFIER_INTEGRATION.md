# Harpocrates Noir Verifier Integration

Tier 1 is now split into two contracts:

- `HarpocratesRegistry`: stores evidence records, prevents duplicate proof IDs, prevents duplicate video hashes, and stores used nullifiers.
- `Noir UltraHonk Verifier`: validates `verify_proof(public_inputs, proof)` with the Silent Witness verification key.

The registry has the production-facing function:

```text
register_anonymous_verified(video_hash, metadata_hash, proof_id, public_inputs, proof)
```

It expects `public_inputs` to be 128 bytes:

```text
field[0] video_hash_hi
field[1] video_hash_lo
field[2] credential_root
field[3] nullifier
```

Noir field elements are 32 bytes. A SHA-256 video hash is split into two 16-byte limbs:

```text
video_hash = low_16_bytes(video_hash_hi) || low_16_bytes(video_hash_lo)
```

The registry verifies that the reconstructed hash matches `video_hash`, checks the nullifier was not used, calls the configured verifier, then stores the proof record.

## Current State

Done:

- Real Noir Silent Witness circuit in `zk/noir/silent_witness`.
- Local UltraHonk proof generation and verification through `bb`.
- Registry verifier configuration with `set_verifier(admin, verifier)`.
- Registry external verifier call through `verify_proof(public_inputs, proof)`.
- Contract test proving the registry calls an external verifier before storing Tier 1.
- PowerShell artifact export script for `proof`, `public_inputs`, and `vk`.
- Testnet UltraHonk verifier deployment for the Silent Witness VK.
- Testnet `register_anonymous_verified` registration through the verifier.
- **Bounded proof aggregation** via `silent_witness_aggregator` circuit and
  `register_batch_verified` contract entry point (NEW).

Not done yet:

- Browser-side proof generation (including the aggregator circuit).

## Recommended Path

Use the existing `rs-soroban-ultrahonk` verifier as the verifier contract, but pin the proving toolchain to the verifier's supported versions before treating on-chain verification as production-grade.

Pinned compatibility point:

```text
Noir 1.0.0-beta.9
bb 0.87.0
```

Current Testnet:

```text
HarpocratesRegistry=CCKPU6ILRLSS3JDU2VUN45J63GDI4YJO7XSJNM6BMA3FQMYE3J4DESEX
SilentWitnessUltraHonkVerifier=CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ
```

Remaining clean path:

1. Generate Silent Witness proofs in the browser or backend worker.
2. Switch frontend Tier 1 registration from `register_anonymous` to `register_anonymous_verified` once dynamic proof generation is available.
3. Replace demo identity secrets with a real credential issuance/nullifier flow.

## Useful Commands

Build and verify the local Noir proof:

```powershell
.\zk\noir\scripts\build-silent-witness-wsl.ps1
.\zk\noir\scripts\prepare-soroban-verifier-artifacts.ps1
```

Build and verify the aggregated proof circuit:

```bash
./zk/noir/scripts/build-silent-witness-aggregator.sh
```

Generate an aggregated proof for multiple video hashes:

```bash
./zk/noir/scripts/generate-silent-witness-aggregator.sh \
  <video-hash-0-hex> <video-hash-1-hex> \
  <credential-secret-field> <nullifier-secret-field>
```

Export generated artifacts as hex:

```powershell
.\zk\noir\scripts\export-silent-witness-artifacts.ps1
```

Build the registry:

```powershell
cd contracts
cargo test
stellar contract build
```

Configure the verifier after deployment:

```powershell
.\contracts\scripts\set-verifier.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -Verifier YOUR_VERIFIER_CONTRACT_ID
```

## Batch Aggregation (`register_batch_verified`)

The registry contract now supports **bounded proof aggregation** via the
`register_batch_verified` entry point.  This accepts a single aggregated
UltraHonk proof (produced by the `silent_witness_aggregator` circuit) that
covers up to **8** video hashes under the same credential identity.

### Public input layout for aggregated proofs

```text
[   0..  32)  domain_separator           – AGGREGATION_DOMAIN_SEPARATOR
[  32.. 160)  element_0                  – video_hash_hi, video_hash_lo,
                                            credential_root, nullifier
[ 160.. 288)  element_1                  – (same layout)
...
[ 928..1056)  element_7                  – (same layout)
```

Each element follows the same 128-byte layout as the individual
`register_anonymous_verified` public inputs.  All credential roots within
the batch must be identical (same identity).

### How batch size works

- The circuit accepts exactly **8** elements (padded with zero video hashes).
- The contract validates the declared batch size matches the public input
  length: `32 + (batch_size * 128)` bytes.
- Each element gets a deterministic sub-proof_id derived from the `batch_id`
  and its element index.
- Per-element nullifiers prevent individual proofs from being replayed outside
  the batch context.
