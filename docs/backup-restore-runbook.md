# Harpocrates Backup & Restore Runbook

## Overview

This runbook documents the automated encrypted backup and restore procedures for
Harpocrates. It covers backup scope, encryption, retention, integrity checks,
restore environment, RPO/RTO boundaries, and key recovery.

## Backup Scope

The backup captures the following artifacts:

| Category | Items | Sensitivity |
|----------|-------|-------------|
| **Configuration** | `.env`, `.env.local`, `config.py`, `Nargo.toml`, `Cargo.toml` | Low (public defaults) |
| **Deployment manifests** | `DEPLOYMENT.md`, `VERIFIER_INTEGRATION.md`, deploy scripts | Medium |
| **CI/CD workflows** | `.github/workflows/*.yml` | Low |
| **Circuit source** | `zk/noir/silent_witness/src/*.nr`, `Prover.toml` | Low (public source) |
| **Contract source** | `contracts/harpocrates-registry/src/*.rs` | Low |
| **Backend source** | `app.py`, `config.py`, `db.py`, `metrics.py`, `noir.py`, `stego.py` | Low |
| **Frontend source** | Key TypeScript/JS files, `package.json`, configs | Low |
| **Git state** | Current commit hash, branch, timestamp | Low |

### Excluded from backup

- Compiled proofs (`*.proof`)
- Media files (`*.mp4`)
- Build artifacts (`target/`, `dist/`)
- Temporary files (`tmp/`)
- Dependencies (`node_modules/`)

## Encryption

Backups are encrypted using **GPG AES256** with the following modes:

1. **GPG recipient** (recommended): Use `--gpg-recipient <key-id>` to encrypt
   to a specific GPG public key.
2. **Symmetric key**: Use `--encryption-key <base64-key>` for password-based
   AES256 encryption.
3. **Auto-generated key**: If no key is provided, a random key is generated and
   printed. The operator must save this key securely.

### Key Recovery Boundaries

- GPG private keys must be stored in a secure offline location (e.g., hardware
  token, encrypted vault).
- Symmetric keys must be shared via out-of-band secure channel.
- Key compromise requires immediate rotation and re-encryption of all backups.

## Retention Policy

- Default retention: **90 days**
- Configurable via `--retention-days <N>` or `RETENTION_DAYS` environment variable
- Old backups are automatically pruned based on file modification time
- CI drill backups are retained for 7 days by default

## Backup Procedure

### Manual Backup

```bash
# With GPG recipient
./scripts/backup.sh \
  --output-dir /path/to/backups \
  --retention-days 90 \
  --gpg-recipient "admin@harpocrates"

# With symmetric key
BACKUP_ENCRYPTION_KEY="your-base64-key" \
  ./scripts/backup.sh \
  --output-dir /path/to/backups

# With auto-generated key
./scripts/backup.sh --output-dir /path/to/backups
# !! SAVE THE GENERATED KEY !!
```

### Automated Backup (CI)

Backup drills run automatically:
- **Weekly**: Sunday at 05:00 UTC via `backup-restore-drill.yml`
- **Manual trigger**: via GitHub Actions workflow dispatch

## Restore Procedure

### Prerequisites

1. Access to the encrypted backup file (`.gpg`)
2. The corresponding decryption key or GPG private key
3. Network access to the target deployment environment

### Manual Restore

```bash
# With GPG key
./scripts/restore.sh backup-file.gpg \
  --output-dir /tmp/restore \
  --gpg-recipient "admin@harpocrates"

# With symmetric key
BACKUP_ENCRYPTION_KEY="your-base64-key" \
  ./scripts/restore.sh backup-file.gpg \
  --output-dir /tmp/restore

# With passphrase prompt
./scripts/restore.sh backup-file.gpg \
  --output-dir /tmp/restore
```

### Restore Verification

The restore script performs the following verifications:

1. **Decryption**: Confirms the backup can be decrypted
2. **Integrity check**: Verifies SHA256 hashes of all files against the manifest
3. **RTO measurement**: Tracks restore duration against the target
4. **Restore plan**: Generates a JSON plan of all files to restore

## RPO / RTO Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| **RPO** (Recovery Point Objective) | 15 minutes | Time since last backup |
| **RTO** (Recovery Time Objective) | 30 minutes | Time to complete restore |

## Integrity Checks

Every backup includes:

1. **Manifest**: JSON file listing all backed-up items with their SHA256 hashes
2. **Manifest integrity**: SHA256 of the manifest itself stored in metadata
3. **Encrypted archive verification**: SHA256 of the final encrypted archive

During restore, all file hashes are verified against the manifest. Any mismatch
aborts the restore process.

## CI Drill Workflow

The `backup-restore-drill.yml` workflow:

1. Generates an ephemeral GPG key for the drill
2. Runs `backup.sh` to create an encrypted backup
3. Uploads the backup as a workflow artifact
4. Runs `restore.sh` to restore from the backup
5. Verifies the restored content
6. Cleans up test GPG keys

This validates that both backup and restore procedures work correctly without
affecting production data.

## Troubleshooting

### Backup fails with "gpg: no valid OpenPGP data"

Ensure GPG is installed and the recipient key exists:
```bash
gpg --list-keys
```

### Restore fails with "Integrity check failed"

The backup may be corrupted or tampered with. Try:
1. Verify the backup file hash against the original
2. Use an older backup if available
3. Check file permissions on the restore directory

### RTO exceeded

If restore takes longer than the RTO target:
1. Check disk I/O and network bandwidth
2. Consider restoring to a smaller directory
3. Verify the backup file is not corrupted

### Decryption fails

1. Confirm you have the correct GPG private key or passphrase
2. Check that the key hasn't expired or been revoked
3. Verify the backup file hasn't been modified since encryption

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Backup file tampering | SHA256 integrity manifest with cross-verification |
| Unauthorized decryption | GPG AES256 encryption with key-bound access |
| Key compromise | Documented key rotation procedure |
| Incomplete backup | Explicit scope definition and manifest validation |
| Restore failure | Automated CI drills with verification |

## Limitations

- Backups do not include compiled proofs or media files (excluded for privacy
  and size reasons)
- Proof metadata in the database requires separate database backup procedures
- Stellar contract state cannot be backed up via this mechanism (use contract
  upgrade patterns)
- Key recovery depends on external key management procedures not covered here
