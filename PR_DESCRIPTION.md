# ci(zk): verify Noir circuit builds and generated artifacts

## Summary

Adds deterministic CI enforcement that Noir circuits build cleanly and that
committed artifacts match the circuit sources pinned in `zk/toolchain.lock.json`.

Closes #8

## Changes

### `zk/toolchain.lock.json`
- Added artifact declarations for the `silent_witness_aggregator` and
  `silent_witness_aggregator_helper` circuits (ACIR, VK, VK fields).

### `zk/noir/scripts/reproducible-build.sh`
- Extended the `CIRCUITS` array to include `silent_witness_aggregator` and
  `silent_witness_aggregator_helper`.
- Generalized the `write_vk` block to also generate verification keys for
  the aggregator circuit (`silent_witness_aggregator`).

### `.github/workflows/zk-ci.yml`
- Added new `circuit-build` job that:
  - Installs the pinned `nargo` and `bb` toolchain versions from the lock file.
  - Verifies installed versions match the lock.
  - Runs `reproducible-build.sh --verify` to build all circuits from clean
    targets and compare normalized digests against the committed manifest.
  - Falls back to `--single` when no manifest is committed yet (inert until
    first publication).

### `docs/zk-reproducible-builds.md`
- Added **Artifact update workflow** section documenting the full workflow
  from editing circuits to publishing browser artifacts and committing.
- Added **CI enforcement** subsection explaining the new `circuit-build` job.
- Added **Adding a new circuit** subsection.

## Test Plan

1. **CI path from a clean checkout**: The `circuit-build` job installs nargo/bb,
   builds all declared circuits, and runs the manifest check. A stale artifact
   causes `EXIT_DRIFT` (code 1) and the job fails.
2. **Existing checks**: `artifact-tooling` (unit tests, lock self-consistency)
   and `conformance-vectors` remain unchanged and pass.
3. **Local verification** (requires pinned toolchain):
   ```bash
   zk/noir/scripts/reproducible-build.sh --verify
   ```
