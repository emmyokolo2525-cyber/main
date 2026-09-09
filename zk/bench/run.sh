#!/usr/bin/env bash
# Hermetic driver for ZK proof/verify benchmarks.
# See docs/zk-benchmarks.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-C}"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"

exec python3 zk/bench/zk_bench.py "$@"
