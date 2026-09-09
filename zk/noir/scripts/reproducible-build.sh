#!/usr/bin/env bash
#
# Hermetic, double-build reproducibility check for the Harpocrates zk artifacts.
#
# Builds every declared circuit twice from a clean target directory, digests the
# normalized artifacts after each build, and fails if the two manifests differ.
# A green run means: these artifacts are a deterministic function of this source
# tree and the toolchain pinned in zk/toolchain.lock.json.
#
# Usage
#   zk/noir/scripts/reproducible-build.sh                 # double build + compare
#   zk/noir/scripts/reproducible-build.sh --single        # one build, write manifest
#   zk/noir/scripts/reproducible-build.sh --verify        # one build, compare to committed manifest
#
# Exit codes (shared with zk/tools/artifact_manifest.py)
#   0  reproducible
#   1  drift detected
#   2  usage error
#   3  fatal (toolchain mismatch, missing artifact, unreadable tree)
#
# Rollback: this script only writes under zk/noir/*/target and the manifest path
# passed to it. Deleting those restores the previous state; no build step here
# mutates tracked source. See docs/zk-reproducible-builds.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOCK="${REPO_ROOT}/zk/toolchain.lock.json"
TOOL="${REPO_ROOT}/zk/tools/artifact_manifest.py"
MANIFEST="${REPO_ROOT}/zk/artifacts.manifest.json"

PYTHON="${PYTHON:-python3}"
MODE="double"

EXIT_OK=0
EXIT_DRIFT=1
EXIT_USAGE=2
EXIT_FATAL=3

# --- signals ---------------------------------------------------------------
# Single-line JSON on stderr, matching the manifest tool. Only state names,
# counts, and versions are ever emitted — never artifact or witness content.
signal() {
  printf '{"event":"%s","detail":"%s"}\n' "$1" "${2:-}" >&2
}

die() {
  signal "build.error" "$1"
  exit "${2:-$EXIT_FATAL}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --single) MODE="single" ;;
    --verify) MODE="verify" ;;
    --manifest) shift; MANIFEST="${1:?--manifest requires a path}" ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit "$EXIT_OK" ;;
    *) signal "usage.error" "unknown argument: $1"; exit "$EXIT_USAGE" ;;
  esac
  shift
done

# --- hermetic environment --------------------------------------------------
# Pinned so nothing host-specific can reach an artifact. Anything that still
# differs between two runs under this environment is a genuine reproducibility
# bug, not a configuration difference.
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C
export LANG=C
export RUST_BACKTRACE=0
export PYTHONHASHSEED=0
umask 022

command -v nargo >/dev/null 2>&1 || die "nargo not on PATH; see zk/noir/README.md"
command -v bb    >/dev/null 2>&1 || die "bb not on PATH; see zk/noir/README.md"
command -v "$PYTHON" >/dev/null 2>&1 || die "python3 not on PATH"
[[ -f "$LOCK" ]] || die "toolchain lock missing: zk/toolchain.lock.json"

# --- toolchain pin ---------------------------------------------------------
lock_value() {
  "$PYTHON" -c "import json,sys;print(json.load(open(sys.argv[1]))$1)" "$LOCK"
}

EXPECTED_NARGO="$(lock_value "['toolchain']['nargo']['version']")"
EXPECTED_BB="$(lock_value "['toolchain']['barretenberg']['version']")"
SCHEME="$(lock_value "['toolchain']['proving_scheme']")"
ORACLE="$(lock_value "['toolchain']['oracle_hash']")"

ACTUAL_NARGO="$(nargo --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?' | head -n1 || true)"
ACTUAL_BB="$(bb --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"

if [[ "$ACTUAL_NARGO" != "$EXPECTED_NARGO" ]]; then
  die "nargo version drift: expected ${EXPECTED_NARGO}, found ${ACTUAL_NARGO:-unknown}"
fi
if [[ "$ACTUAL_BB" != "$EXPECTED_BB" ]]; then
  die "bb version drift: expected ${EXPECTED_BB}, found ${ACTUAL_BB:-unknown}"
fi
signal "toolchain.pinned" "nargo=${ACTUAL_NARGO} bb=${ACTUAL_BB}"

# --- circuits --------------------------------------------------------------
CIRCUITS=(
  "silent_witness"
  "silent_witness_helper"
  "silent_witness_aggregator"
  "silent_witness_aggregator_helper"
  "revocation_witness"
  "revocation_witness_helper"
)

build_once() {
  local label="$1"
  signal "build.start" "$label"

  for circuit in "${CIRCUITS[@]}"; do
    local dir="${REPO_ROOT}/zk/noir/${circuit}"
    [[ -d "$dir" ]] || { signal "circuit.skipped" "$circuit"; continue; }

    # Clean target so a stale artifact can never be mistaken for a fresh one.
    rm -rf "${dir}/target"

    ( cd "$dir" && nargo check && nargo compile ) \
      || die "nargo compile failed for ${circuit}"

    signal "circuit.compiled" "$circuit"
  done

  # --- write_vk: verification keys for the primary circuits ---
  # The VK is what the on-chain verifier is bound to, so it is part of
  # the reproducibility surface.
  for circuit in silent_witness silent_witness_aggregator; do
    local dir="${REPO_ROOT}/zk/noir/${circuit}"
    local json="${dir}/target/${circuit}.json"
    if [[ -f "$json" ]]; then
      ( cd "$dir" && bb write_vk \
          --scheme "$SCHEME" \
          --oracle_hash "$ORACLE" \
          --bytecode_path "./target/${circuit}.json" \
          --output_path ./target \
          --output_format bytes_and_fields ) \
        || die "bb write_vk failed for ${circuit}"

      # bb has shipped both file and directory layouts for these outputs;
      # normalize to the file layout so the manifest paths stay stable.
      for name in vk vk_fields.json; do
        if [[ -d "${dir}/target/${name}" && -f "${dir}/target/${name}/${name}" ]]; then
          mv "${dir}/target/${name}/${name}" "${dir}/target/${name}.tmp"
          rmdir "${dir}/target/${name}"
          mv "${dir}/target/${name}.tmp" "${dir}/target/${name}"
        fi
      done
      signal "vk.written" "${circuit}"
    fi
  done

  signal "build.done" "$label"
}

write_manifest() {
  "$PYTHON" "$TOOL" --lock "$LOCK" write --output "$1"
}

case "$MODE" in
  single)
    build_once "single"
    write_manifest "$MANIFEST" || exit "$EXIT_FATAL"
    signal "run.ok" "manifest written"
    exit "$EXIT_OK"
    ;;

  verify)
    build_once "verify"
    set +e
    "$PYTHON" "$TOOL" --lock "$LOCK" verify --manifest "$MANIFEST"
    status=$?
    set -e
    exit "$status"
    ;;

  double)
    WORK="$(mktemp -d)"
    # Always clean up, including on cancellation, so a interrupted run leaves
    # no partial manifests behind for a later run to trust.
    trap 'rm -rf "$WORK"' EXIT INT TERM

    build_once "first"
    write_manifest "${WORK}/first.json" || exit "$EXIT_FATAL"

    build_once "second"
    write_manifest "${WORK}/second.json" || exit "$EXIT_FATAL"

    set +e
    "$PYTHON" "$TOOL" --lock "$LOCK" compare "${WORK}/first.json" "${WORK}/second.json"
    status=$?
    set -e

    if [[ $status -ne 0 ]]; then
      signal "run.failed" "builds are not reproducible"
      exit "$status"
    fi

    cp "${WORK}/second.json" "$MANIFEST"
    signal "run.ok" "reproducible; manifest written"
    exit "$EXIT_OK"
    ;;
esac
