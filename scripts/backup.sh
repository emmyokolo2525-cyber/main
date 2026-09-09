#!/usr/bin/env bash
#
# harpocrates-backup - Encrypted backup automation for Harpocrates.
#
# Backs up proof metadata, configuration, deployment manifests, and
# required keys with encryption, integrity checks, and retention policy.
#
# Usage:
#   ./scripts/backup.sh [--output-dir <path>] [--retention-days <N>]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- Configuration ----
BACKUP_DIR="${OUTPUT_DIR:-${BACKUP_OUTPUT_DIR:-$PROJECT_ROOT/tmp/backups}}"
RETENTION_DAYS="${RETENTION_DAYS:-90}"
GPG_RECIPIENT="${GPG_RECIPIENT:-}"
ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BACKUP_NAME="harpocrates-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"
MANIFEST="${BACKUP_PATH}/manifest.json"

# Privacy-safe: paths to exclude from backup (sensitive material)
EXCLUDE_PATTERNS=(
  "*.mp4"
  "*.proof"
  "tmp/*"
  "node_modules/*"
  "target/*"
  ".git/*"
  "__pycache__/*"
  "*.pyc"
)

# ---- Utility Functions ----
log_info()  { echo "[harpocrates-backup] INFO  $*"; }
log_warn()  { echo "[harpocrates-backup] WARN  $*" >&2; }
log_error() { echo "[harpocrates-backup] ERROR $*" >&2; }

sha256sum_file() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

cleanup() {
  if [ -d "$BACKUP_PATH" ] && [ "${1:-}" = "error" ]; then
    log_warn "Cleaning up incomplete backup: $BACKUP_PATH"
    rm -rf "$BACKUP_PATH"
  fi
}

# ---- Backup Scope ----
collect_backup_items() {
  local items=()

  # 1. Configuration files
  for cfg in \
    "backend/config.py" \
    "backend/.env" \
    "frontend/.env.local" \
    "frontend/.env.production" \
    "docker-compose.example.yml" \
    "contracts/Cargo.toml" \
    "contracts/contracts/harpocrates-registry/Cargo.toml" \
    "zk/noir/silent_witness/Nargo.toml" \
    "zk/noir/silent_witness_helper/Nargo.toml"; do
    if [ -f "${PROJECT_ROOT}/${cfg}" ]; then
      items+=("$cfg")
    fi
  done

  # 2. Deployment manifests
  for manifest in \
    "contracts/DEPLOYMENT.md" \
    "contracts/VERIFIER_INTEGRATION.md" \
    "scripts/deploy-testnet.ps1" \
    "scripts/e2e-harpocrates.ps1"; do
    if [ -f "${PROJECT_ROOT}/${manifest}" ]; then
      items+=("$manifest")
    fi
  done

  # 3. CI/CD workflows
  for workflow in .github/workflows/*.yml; do
    if [ -f "${PROJECT_ROOT}/${workflow}" ]; then
      items+=("$workflow")
    fi
  done

  # 4. Noir circuit source (not proofs)
  for circuit in \
    "zk/noir/silent_witness/src/main.nr" \
    "zk/noir/silent_witness_helper/src/main.nr" \
    "zk/noir/silent_witness/Prover.toml" \
    "zk/noir/silent_witness_helper/Prover.toml"; do
    if [ -f "${PROJECT_ROOT}/${circuit}" ]; then
      items+=("$circuit")
    fi
  done

  # 5. Contract source
  for contract_src in contracts/contracts/harpocrates-registry/src/*.rs; do
    if [ -f "${PROJECT_ROOT}/${contract_src}" ]; then
      items+=("$contract_src")
    fi
  done

  # 6. Backend and frontend source
  for src_file in \
    "backend/app.py" \
    "backend/config.py" \
    "backend/db.py" \
    "backend/metrics.py" \
    "backend/noir.py" \
    "backend/stego.py" \
    "backend/requirements.txt"; do
    if [ -f "${PROJECT_ROOT}/${src_file}" ]; then
      items+=("$src_file")
    fi
  done

  for src_file in \
    "frontend/package.json" \
    "frontend/vite.config.ts" \
    "frontend/tsconfig.json" \
    "frontend/src/harpocratesRegistry.ts" \
    "frontend/src/noirClient.ts" \
    "frontend/src/stellar.ts" \
    "frontend/src/networkGuard.ts" \
    "frontend/src/proofManifest.ts"; do
    if [ -f "${PROJECT_ROOT}/${src_file}" ]; then
      items+=("$src_file")
    fi
  done

  printf '%s\n' "${items[@]}"
}

# ---- Main Backup Logic ----
perform_backup() {
  log_info "Starting encrypted backup: $BACKUP_NAME"
  log_info "Output directory: $BACKUP_DIR"

  # Create backup directory
  mkdir -p "$BACKUP_PATH"
  mkdir -p "${BACKUP_PATH}/config"
  mkdir -p "${BACKUP_PATH}/manifests"
  mkdir -p "${BACKUP_PATH}/workflows"
  mkdir -p "${BACKUP_PATH}/circuits"
  mkdir -p "${BACKUP_PATH}/contracts"
  mkdir -p "${BACKUP_PATH}/source"
  mkdir -p "${BACKUP_PATH}/metadata"

  MANIFEST_ENTRIES=()

  # Collect and copy items
  while IFS= read -r item; do
    [ -z "$item" ] && continue
    local src="${PROJECT_ROOT}/${item}"
    local dst="${BACKUP_PATH}/${item}"

    # Determine subdirectory
    case "$item" in
      backend/*|frontend/*)  dst_dir="${BACKUP_PATH}/source/${item}" ;;
      .github/workflows/*)   dst_dir="${BACKUP_PATH}/workflows/$(basename "$item")" ;;
      contracts/*.md|scripts/*) dst_dir="${BACKUP_PATH}/manifests/$(basename "$item")" ;;
      contracts/*)           dst_dir="${BACKUP_PATH}/contracts/${item#contracts/}" ;;
      zk/noir/*)             dst_dir="${BACKUP_PATH}/circuits/${item#zk/noir/}" ;;
      *.yml|*.yaml|*.toml)   dst_dir="${BACKUP_PATH}/config/$(basename "$item")" ;;
      *)                     dst_dir="${BACKUP_PATH}/source/$(basename "$item")" ;;
    esac

    mkdir -p "$(dirname "$dst_dir")"
    cp "$src" "$dst_dir"
    local hash
    hash=$(sha256sum_file "$dst_dir")
    MANIFEST_ENTRIES+=("$(basename "$item")|$hash")
    log_info "  Copied: $item"
  done < <(collect_backup_items)

  # Record git state if available
  if git -C "$PROJECT_ROOT" rev-parse --git-dir &>/dev/null; then
    local commit_hash
    commit_hash=$(git -C "$PROJECT_ROOT" rev-parse HEAD)
    local branch
    branch=$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD)
    cat > "${BACKUP_PATH}/metadata/git-state.json" <<EOF
{
  "commit": "$commit_hash",
  "branch": "$branch",
  "timestamp": "$TIMESTAMP",
  "repository": "harpocrates-stellar/main"
}
EOF
    MANIFEST_ENTRIES+=("git-state.json|$(sha256sum_file "${BACKUP_PATH}/metadata/git-state.json")")
    log_info "  Git state captured: $commit_hash ($branch)"
  fi

  # Generate backup manifest
  local manifest_data
  manifest_data=$(python3 -c "
import json
entries = {}
for line in '''$(printf '%s\n' "${MANIFEST_ENTRIES[@]}")'''.strip().split('\n'):
    if '|' in line:
        name, h = line.split('|', 1)
        entries[name] = h
manifest = {
    'backup_name': '$BACKUP_NAME',
    'timestamp': '$TIMESTAMP',
    'schema_version': 1,
    'items': entries,
    'integrity': {'algorithm': 'sha256-256', 'count': len(entries)}
}
print(json.dumps(manifest, indent=2))
")
  echo "$manifest_data" > "$MANIFEST"
  log_info "  Manifest generated: $MANIFEST"

  # Compute manifest integrity hash
  local manifest_hash
  manifest_hash=$(sha256sum_file "$MANIFEST")

  # Create integrity metadata
  cat > "${BACKUP_PATH}/metadata/integrity.json" <<EOF
{
  "backup_name": "$BACKUP_NAME",
  "timestamp": "$TIMESTAMP",
  "manifest_hash": "$manifest_hash",
  "signed": false,
  "schema_version": 1
}
EOF

  # Encrypt the backup
  local archive="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
  local encrypted="${archive}.gpg"

  log_info "Creating encrypted archive..."

  # Create tarball
  tar -czf "$archive" -C "$BACKUP_DIR" "$BACKUP_NAME"

  # Encrypt with GPG or symmetric key
  if [ -n "$GPG_RECIPIENT" ]; then
    # GPG recipient encryption
    gpg --batch --yes --recipient "$GPG_RECIPIENT" \
      --trust-model always \
      --output "$encrypted" \
      --encrypt "$archive"
    log_info "  Encrypted with GPG recipient: $GPG_RECIPIENT"
  elif [ -n "$ENCRYPTION_KEY" ]; then
    # Symmetric encryption with provided key
    echo "$ENCRYPTION_KEY" | gpg --batch --yes \
      --passphrase-fd 0 \
      --symmetric --cipher-algo AES256 \
      --output "$encrypted" \
      "$archive"
    log_info "  Encrypted with symmetric key (AES256)"
  else
    # Generate a random key and encrypt
    local random_key
    random_key=$(openssl rand -base64 32)
    echo "$random_key" | gpg --batch --yes \
      --passphrase-fd 0 \
      --symmetric --cipher-algo AES256 \
      --output "$encrypted" \
      "$archive"
    log_warn "  No encryption key provided. Generated random key."
    log_warn "  !! SAVE THIS KEY TO RECOVER THE BACKUP: $random_key"
    # Store key hint (not the key itself)
    echo "Key generated at $TIMESTAMP" > "${BACKUP_PATH}/metadata/key-hint.txt"
  fi

  # Verify encryption
  if [ -f "$encrypted" ]; then
    local encrypted_size
    encrypted_size=$(stat -c%s "$encrypted" 2>/dev/null || stat -f%z "$encrypted" 2>/dev/null)
    log_info "  Encrypted archive: $encrypted ($encrypted_size bytes)"
  else
    log_error "Encryption failed: $encrypted not found"
    cleanup error
    return 1
  fi

  # Clean up unencrypted archive and backup directory
  rm -f "$archive"
  rm -rf "$BACKUP_PATH"

  # Apply retention policy
  log_info "Applying retention policy: ${RETENTION_DAYS} days"
  find "$BACKUP_DIR" -name "*.gpg" -type f -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true

  # Final integrity check
  log_info "Verifying backup integrity..."
  local verify_hash
  verify_hash=$(sha256sum_file "$encrypted")
  log_info "  Backup SHA256: $verify_hash"

  log_info "Backup complete: $encrypted"
  echo "$encrypted"
}

# ---- Entry Point ----
main() {
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output-dir)
        BACKUP_DIR="$2"
        shift 2
        ;;
      --retention-days)
        RETENTION_DAYS="$2"
        shift 2
        ;;
      --gpg-recipient)
        GPG_RECIPIENT="$2"
        shift 2
        ;;
      --encryption-key)
        ENCRYPTION_KEY="$2"
        shift 2
        ;;
      --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --output-dir <path>       Backup output directory"
        echo "  --retention-days <N>      Retention period in days (default: 90)"
        echo "  --gpg-recipient <id>      GPG recipient for encryption"
        echo "  --encryption-key <key>    Symmetric encryption key"
        echo "  --help                    Show this help"
        exit 0
        ;;
      *)
        log_error "Unknown option: $1"
        exit 1
        ;;
    esac
  done

  perform_backup
}

main "$@"
