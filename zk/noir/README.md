# Harpocrates Noir Circuits

This folder contains the real Noir path for Tier 1 Silent Witness,
including the bounded proof aggregation circuit.

## Circuits

### `silent_witness`

The base circuit proves:

- the prover knows a private `credential_secret`
- the public `credential_root` is derived from that secret
- the public `nullifier` is bound to `credential_secret`, `nullifier_secret`, `video_hash_hi`, and `video_hash_lo`

The creator can register evidence without revealing the credential secret.

### `silent_witness_aggregator` (NEW)

Bounded aggregation circuit that bundles up to **8** individual Silent Witness
proofs into a single verifiable UltraHonk proof.  All video hashes in the
batch must be bound to the same credential identity.

Key properties:

- **MAX_AGGREGATION_SIZE = 8**: fixed upper bound enforced at circuit and
  contract level.
- **Same-identity binding**: all `credential_root` values in the batch must
  match the root derived from the private `credential_secret`.
- **Per-element nullifiers**: each video hash gets its own nullifier,
  preventing replay of individual elements from the batch.
- **Versioned domain separator**: the circuit is bound to a protocol version
  tag, preventing cross-version proof replay.

### `silent_witness_aggregator_helper` (NEW)

Helper circuit that derives batch public inputs (`credential_root` and
`nullifier` for each element) from private secrets and video hashes.

## Tooling

Noir's official installation path uses `noirup`/`nargo`. Barretenberg (`bb`) is the proving backend. On Windows, the official Noir docs recommend using WSL for the full toolchain.

Inside WSL:

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
source ~/.bashrc
noirup

curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
source ~/.bashrc
bbup
```

## Reproducible builds

Toolchain versions, the hermetic environment, artifact normalization rules, and
resource limits are pinned in [`zk/toolchain.lock.json`](../toolchain.lock.json).
The double-build reproducibility check is:

```bash
zk/noir/scripts/reproducible-build.sh          # build twice, compare, write manifest
zk/noir/scripts/reproducible-build.sh --verify # build once, compare to the committed manifest
python -m pytest zk/tools -q                   # tooling unit tests, no toolchain needed
```

See [docs/zk-reproducible-builds.md](../../docs/zk-reproducible-builds.md).

## Benchmarks

Cold/warm proof generation and verification baselines (browser, native, CI,
Soroban-adjacent) live under `zk/bench/`:

```bash
python -m pytest zk/bench -q
zk/bench/run.sh run --target ci --synthetic
```

See [docs/zk-benchmarks.md](../../docs/zk-benchmarks.md).

## Cross-layer conformance

The public-input codec shared by the backend, browser, and Soroban registry is
pinned by [`zk/vectors/verifier_conformance_v1.json`](../vectors/verifier_conformance_v1.json).
See [docs/zk-conformance-vectors.md](../../docs/zk-conformance-vectors.md) and
[docs/zk-fuzzing.md](../../docs/zk-fuzzing.md).

## Build

For the full local build with the checked-in prover file:

```bash
cd zk/noir/silent_witness
nargo check
nargo execute witness
bb prove --scheme ultra_honk --oracle_hash keccak --bytecode_path ./target/silent_witness.json --witness_path ./target/witness.gz --output_path ./target --output_format bytes_and_fields
bb write_vk --scheme ultra_honk --oracle_hash keccak --bytecode_path ./target/silent_witness.json --output_path ./target --output_format bytes_and_fields
bb verify --scheme ultra_honk --oracle_hash keccak --vk_path ./target/vk --proof_path ./target/proof --public_inputs_path ./target/public_inputs
```

Current local proof status:

```text
nargo version = 1.0.0-beta.9
bb version = 0.87.0
silent_witness proof verified successfully with UltraHonk
```

From PowerShell on Windows:

```powershell
.\zk\noir\scripts\build-silent-witness-wsl.ps1
```

Generate proof artifacts for a specific video hash:

```powershell
.\zk\noir\scripts\generate-silent-witness-wsl.ps1 `
  -VideoHash YOUR_32_BYTE_HEX `
  -CredentialSecret YOUR_FIELD_DECIMAL `
  -NullifierSecret YOUR_FIELD_DECIMAL
```

## Browser Prover

The React app serves the compiled circuit artifacts from:

```text
frontend/public/noir/silent_witness.json
frontend/public/noir/silent_witness_helper.json
```

The browser flow runs the helper circuit first to derive `credential_root` and
`nullifier`, then runs `silent_witness` and produces an UltraHonk proof with
`@aztec/bb.js` using Keccak challenges. Smoke-test the same path in Node:

```powershell
cd frontend
node scripts/test-noir-client-prover.mjs
```

Export proof artifacts as hex for Soroban tooling:

```powershell
.\zk\noir\scripts\prepare-soroban-verifier-artifacts.ps1
.\zk\noir\scripts\export-silent-witness-artifacts.ps1
```

## Soroban Integration

The Soroban registry now has two Tier 1 entrypoints:

- `register_anonymous`: development/demo boundary.
- `register_anonymous_verified`: production-facing path that calls an external `verify_proof(public_inputs, proof)` contract.

The expected public input order is:

```text
video_hash_hi
video_hash_lo
credential_root
nullifier
```

Stellar's official privacy docs currently highlight deployable Groth16 verifier examples, while Noir/UltraHonk-on-Soroban is an emerging path. Harpocrates keeps the UltraHonk verifier isolated behind a small contract interface so the registry API can stay stable.

See `contracts/VERIFIER_INTEGRATION.md` for the remaining on-chain verifier deployment step.
