# Security Policy

Harpocrates is a privacy-preserving evidence protocol. Responsible disclosure
of vulnerabilities helps protect witnesses, sources, and the integrity of
registered evidence.

## Supported Versions

Only the current `main` branch is supported. This is a Stellar **Testnet**
deployment. No production or mainnet instance is currently operated; the
version table below reflects the active development line.

| Version / Branch | Supported |
|-----------------|-----------|
| `main` (HEAD)   | ✅ Yes    |
| Any older fork  | ❌ No     |

## Security Scope

The following components are in scope for vulnerability reports:

- **Soroban smart contracts** (`contracts/`) — registry logic, issuer/verifier
  allowlists, nullifier replay protection, credential-root lifecycle.
- **Flask backend** (`backend/`) — video steganography service, NeonDB proof
  persistence, API input validation, security headers, CORS configuration.
- **React frontend** (`frontend/`) — Evidence Studio, Verification Portal,
  client-side Noir proving, seed vault and safe storage, network guard.
- **Noir ZK circuit** (`zk/noir/silent_witness`) — circuit correctness,
  soundness, and nullifier uniqueness.
- **CI/CD workflows** (`.github/workflows/`) — supply-chain and secret exposure
  issues.

Out of scope:

- Stellar Testnet infrastructure operated by the Stellar Development Foundation.
- Third-party dependencies (report those upstream; note them here if they
  directly affect Harpocrates users).
- Theoretical attacks with no practical exploitation path on Testnet.
- Cosmetic or UX issues that carry no security consequence.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately using one of the following channels:

1. **GitHub private security advisory (preferred)**
   Navigate to
   `https://github.com/harpocrates-stellar/main/security/advisories/new`
   and submit a draft advisory. The maintainer (@enliven17) will be notified
   immediately and the report stays confidential until a fix is released.

2. **Direct contact**
   If the advisory flow is unavailable, email or DM @enliven17 directly via
   GitHub (`https://github.com/enliven17`). Include "Harpocrates Security" in
   the subject line.

Please include in your report:

- A clear description of the vulnerability and the affected component.
- Steps to reproduce or a proof-of-concept (kept private).
- The potential impact (e.g., nullifier bypass, credential-root forgery,
  steganographic integrity break, secret exposure).
- Any suggested mitigations you have already identified.

## ⚠️ Warning: Do Not Publish Witness Secrets or Exploitable Proof Details

Harpocrates witnesses rely on the secrecy of their credential secret and
nullifier secret to remain anonymous. **Never include real witness secrets,
nullifier preimages, or exploitable ZK proof details in a public issue,
pull request, commit message, or discussion thread.** Even on Testnet, leaking
these values could de-anonymise a real person who re-used secrets across
environments.

If your report involves a flaw in the Silent Witness circuit or credential-root
allowlist, treat all proof artifacts as sensitive and share them only through
the private channels described above.

## Acknowledgement and Remediation Process

1. **Acknowledgement** — The maintainer will acknowledge receipt within
   **48 hours** of a private report.
2. **Triage** — Within **7 days** the maintainer will confirm whether the issue
   is accepted as a vulnerability, request clarification, or explain why it
   falls out of scope.
3. **Fix and disclosure timeline** — For accepted vulnerabilities, a target fix
   date will be agreed with the reporter. Critical issues (e.g., nullifier
   bypass, arbitrary registry write) will be prioritised for immediate patching.
   A coordinated public disclosure will follow once a fix is merged.
4. **Credit** — Reporters who wish to be credited will be acknowledged in the
   release notes or advisory unless they prefer to remain anonymous.

## References

- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — full threat model including attack
  scenarios, mitigations, and open risks.
- [`CODEOWNERS`](./.github/CODEOWNERS) — repository maintainer.
- [Stellar Vulnerability Disclosure](https://www.stellar.org/bug-bounty-program)
  — for issues in the Stellar network itself.
