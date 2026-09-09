#!/usr/bin/env bash
#
# harpocrates-restore - Encrypted restore automation for Harpocrates.
#
# Restores proof metadata, configuration, deployment manifests, and
# required keys from encrypted backups created by backup.sh.
#
# Usage:
#   ./scripts/restore.sh <backup-file.gpg> [--output-dir <path>] [--encryption-key <key>]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- Configuration ----
RESTORE_DIR="${RESTORE_DIR:-$PROJECT_ROOT/tmp/restore}"
ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
GPG_RECIPIENT="${GPG_RECIPIENT:-}"
RPO_TARGET_MINUTES="${RPO_TARGET_MINUTES:-15}"
RTO_TARGET_MINUTES="${RTO_TARGET_MINUTES:-30}"

# ---- Utility Functions ----
log_info()  { echo "[harpocrates-restore] INFO  $*"; }
log_warn()  { echo "[harpocrates-restore] WARN  $*" >&2; }
log_error() { echo "[harpocrates-restore] ERROR $*" >&2; }

sha256sum_file() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

cleanup() {
  if [ -d "$RESTORE_DIR" ] && [ "${1:-}" = "error" ]; then
    log_warn "Cleaning up incomplete restore: $RESTORE_DIR"
    rm -rf "$RESTORE_DIR"
  fi
}

# ---- Integrity Verification ----
verify_integrity() {
  local manifest="$1"
  log_info "Verifying backup integrity..."

  if [ ! -f "$manifest" ]; then
    log_error "Manifest not found: $manifest"
    return 1
  fi

  local manifest_hash
  manifest_hash=$(sha256sum_file "$manifest")
  log_info "  Manifest hash: $manifest_hash"

  local items
  items=$(python3 -c "
import json
with open('$manifest') as f:
    m = json.load(f)
for name, h in m.get('items', {}).items():
    print(f'{name}|{h}')
")

  local errors=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local name="${line%%|*}"
    local expected_hash="${line#*|}"
    local file_path
    file_path=$(find "$RESTORE_DIR" -name "$name" -type f 2>/dev/null | head -1)

    if [ -z "$file_path" ]; then
      log_warn "  Missing file: $name"
      errors=$((errors + 1))
      continue
    fi

    local actual_hash
    actual_hash=$(sha256sum_file "$file_path")
    if [ "$actual_hash" != "$expected_hash" ]; then
      log_error "  Integrity failure: $name (expected: $expected_hash, got: $actual_hash)"
      errors=$((errors + 1))
    else
      log_info "  Verified: $name"
    fi
  done <<< "$items"

  if [ "$errors" -gt 0 ]; then
    log_error "Integrity check failed with $errors error(s)"
    return 1
  fi

  log_info "Integrity check passed: all items verified"
  return 0
}

# ---- Main Restore Logic ----
perform_restore() {
  local backup_file="$1"
  local restore_start
  restore_start=$(date +%s)

  if [ ! -f "$backup_file" ]; then
    log_error "Backup file not found: $backup_file"
    return 1
  fi

  log_info "Starting restore from: $backup_file"
  log_info "RPO target: ${RPO_TARGET_MINUTES} minutes"
  log_info "RTO target: ${RTO_TARGET_MINUTES} minutes"

  # Create restore directory
  mkdir -p "$RESTORE_DIR"

  # Decrypt the backup
  local decrypted="${RESTORE_DIR}/restore.tar.gz"
  log_info "Decrypting backup..."

  if [ -n "$GPG_RECIPIENT" ]; then
    gpg --batch --yes --recipient "$GPG_RECIPIENT" \
      --trust-model always \
      --output "$decrypted" \
      --decrypt "$backup_file"
  elif [ -n "$ENCRYPTION_KEY" ]; then
    echo "$ENCRYPTION_KEY" | gpg --batch --yes \
      --passphrase-fd 0 \
      --output "$decrypted" \
      --decrypt "$backup_file"
  else
    # Try without passphrase (key stored in agent)
    gpg --batch --yes \
      --output "$decrypted" \
      --decrypt "$backup_file" 2>/dev/null || {
      # Prompt for passphrase
      log_info "Enter decryption passphrase:"
      gpg --batch --yes \
        --output "$decrypted" \
        --decrypt "$backup_file"
    }
  fi

  if [ ! -f "$decrypted" ]; then
    log_error "Decryption failed"
    return 1
  fi
  log_info "  Decryption successful"

  # Extract the archive
  log_info "Extracting backup..."
  tar -xzf "$decrypted" -C "$RESTORE_DIR"
  rm -f "$decrypted"

  # Find the backup directory
  local backup_dir
  backup_dir=$(find "$RESTORE_DIR" -name "manifest.json" -type f -exec dirname {} \; 2>/dev/null | head -1)

  if [ -z "$backup_dir" ]; then
    log_error "Could not find manifest.json in extracted backup"
    return 1
  fi

  log_info "  Extracted to: $backup_dir"

  # Verify integrity
  if ! verify_integrity "${backup_dir}/manifest.json"; then
    log_error "Restore aborted: integrity verification failed"
    return 1
  fi

  # Prepare restore plan
  local plan_file="${RESTORE_DIR}/restore-plan.json"
  python3 -c "
import json, os

backup_dir = '$backup_dir'
plan = {
    'restore_timestamp': '$(date -u +"%Y-%m-%dT%H:%M:%SZ")',
    'backup_name': os.path.basename(backup_dir),
    'target': '$PROJECT_ROOT',
    'rpo_minutes': $RPO_TARGET_MINUTES,
    'rto_minutes': $RTO_TARGET_MINUTES,
    'files': []
}

# Walk the backup directory
for root, dirs, files in os.walk(backup_dir):
    if '.git' in root:
        continue
    for f in files:
        if f == 'manifest.json':
            continue
        src = os.path.join(root, f)
        rel = os.path.relpath(src, backup_dir)
        plan['files'].append({
            'source': src,
            'relative': rel,
            'size': os.path.getsize(src)
        })

plan['total_files'] = len(plan['files'])
plan['total_bytes'] = sum(f['size'] for f in plan['files'])

with open('$plan_file', 'w') as fp:
    json.dump(plan, fp, indent=2)

print(f'Restore plan: {plan[\"total_files\"]} files, {plan[\"total_bytes\"]} bytes')
"
  log_info "  Restore plan: $plan_file"

  # RTO tracking
  local restore_end
  restore_end=$(date +%s)
  local restore_duration=$((restore_end - restore_start))
  local rto_seconds=$((RTO_TARGET_MINUTES * 60))

  if [ "$restore_duration" -gt "$rto_seconds" ]; then
    log_warn "RTO exceeded: ${restore_duration}s (target: ${rto_seconds}s)"
  else
    log_info "RTO met: ${restore_duration}s (target: ${rto_seconds}s)"
  fi

  # Display restore summary
  log_info "Restore prepared successfully"
  log_info "  Backup: $(basename "$backup_file")"
  log_info "  Restore path: $RESTORE_DIR"
  log_info "  Duration: ${restore_duration}s"

  cat "$plan_file"
}

# ---- Entry Point ----
main() {
  if [ $# -lt 1 ]; then
    log_error "Usage: $0 <backup-file.gpg> [options]"
    echo ""
    echo "Options:"
    echo "  --output-dir <path>      Restore output directory"
    echo "  --encryption-key <key>   Decryption key"
    echo "  --gpg-recipient <id>     GPG recipient"
    echo "  --rpo-minutes <N>        RPO target in minutes (default: 15)"
    echo "  --rto-minutes <N>        RTO target in minutes (default: 30)"
    echo "  --help                   Show this help"
    exit 1
  fi

  local backup_file="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output-dir)
        RESTORE_DIR="$2"
        shift 2
        ;;
      --encryption-key)
        ENCRYPTION_KEY="$2"
        shift 2
        ;;
      --gpg-recipient)
        GPG_RECIPIENT="$2"
        shift 2
        ;;
      --rpo-minutes)
        RPO_TARGET_MINUTES="$2"
        shift 2
        ;;
      --rto-minutes)
        RTO_TARGET_MINUTES="$2"
        shift 2
        ;;
      --help|-h)
        echo "Usage: $0 <backup-file.gpg> [options]"
        exit 0
        ;;
      *)
        log_error "Unknown option: $1"
        exit 1
        ;;
    esac
  done

  perform_restore "$backup_file"
}

main "$@"
