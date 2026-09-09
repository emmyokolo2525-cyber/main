# System Architecture & Trust Boundaries

## 1. Executive Summary

This document details the high-level architecture, module boundaries, trust domains, and end-to-end evidence lifecycle across the platform.

---

## 2. System Component Boundaries

```text
+-----------------------------------------------------------------------------------+
|                                   FRONTEND                                        |
|                          (Next.js / React / Client)                               |
+----------------------------------------+------------------------------------------+
                                         |
                       HTTPS / REST      |      Direct Wallet / RPC Invocations
                   +---------------------+---------------------+
                   |                                           |
                   v                                           v
+------------------------------------+       +------------------------------------+
|              BACKEND               |       |         SOROBAN CONTRACTS          |
|        (Node.js / Express)         |       |      (Stellar Blockchain)          |
+------------------+-----------------+       +------------------------------------+
                   |
     Prisma / SQL  |
                   v
+------------------------------------+       +------------------------------------+
|               NEONDB               |       |           NOIR CIRCUITS            |
|       (Serverless Postgres)        |       |        (Client-Side ZK Prover)     |
+------------------------------------+       +------------------------------------+

```

## 3. Trust Boundaries & Security Lifecycle

```bash
[ Client Domain (Untrusted) ] ------------> [ Smart Contract / Network Domain (Trusted) ]
  • Private Keys / Wallet                     • Soroban On-Chain Execution
  • Raw Private Data                          • ZK Proof Verification
  • Local Noir Prover (WASM)                  • Immutable State Ledger
```

## End-to-End Evidence Lifecycle

```bash
👉🏻 Generation (Client Domain): Private inputs are processed locally via Noir ZK circuits within the client sandbox.

👉🏻 Proof Emission: Noir emits a zero-knowledge proof (\pi) and public inputs (x). Raw secrets never leave the client browser.

👉🏻 Submission: The frontend submits the proof (\pi) and public inputs (x) directly to the Soroban smart contract via Stellar RPC.

👉🏻 On-Chain Verification: The Soroban contract verifies the proof integrity against on-chain verification keys before altering contract state.

👉🏻 Off-Chain Indexing: Upon on-chain transaction confirmation, the backend indexes the verified transaction hash into NeonDB for fast querying.
```
