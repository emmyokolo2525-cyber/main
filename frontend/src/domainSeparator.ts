/**
 * Harpocrates — Versioned Domain Separator
 *
 * Proof statements are bound to a specific (protocol, circuit_version, network)
 * triple so a proof generated for one deployment cannot be replayed in another.
 *
 * How it works
 * ─────────────
 * The three components are encoded as BN254 field elements and hashed with
 * Pedersen inside the Noir circuit:
 *
 *   domain_tag = pedersen_hash([protocol_field, version_field, network_field])
 *
 * The circuit asserts domain_tag == expected_domain_tag at prove-time.
 * The on-chain registry contract independently re-derives the expected tag
 * from its embedded constants and rejects any proof whose tag does not match.
 *
 * In practice the browser does NOT compute Pedersen directly — the helper
 * circuit (`silent_witness_helper`) returns the domain_tag alongside
 * credential_root and nullifier so the prover receives the correct value
 * without reproducing Pedersen in JavaScript.
 *
 * This file exposes:
 *   - The human-readable domain descriptor (`DomainDescriptor`, `buildDomain`)
 *   - The canonical serialisation used to produce the field constants
 *   - The version string that must be bumped on every circuit change
 *
 * Versioning strategy
 * ────────────────────
 * | Change                                  | Action                           |
 * |-----------------------------------------|----------------------------------|
 * | Circuit constraint or R1CS change       | Bump CIRCUIT_VERSION             |
 * | New trusted-setup ceremony              | Bump CIRCUIT_VERSION             |
 * | Different network deployment            | Change NETWORK ("testnet"/"mainnet") |
 * | Protocol-level breaking change          | Bump PROTOCOL_NAME + CIRCUIT_VERSION |
 *
 * After bumping, update DOMAIN_*_FIELD constants in both Noir files:
 *   zk/noir/silent_witness/src/main.nr
 *   zk/noir/silent_witness_helper/src/main.nr
 * and redeploy the contract with the new embedded expected_domain_tag.
 */

/** Supported deployment networks. */
export type Network = 'testnet' | 'mainnet'

/** A fully-qualified domain context for a Silent Witness proof. */
export interface DomainDescriptor {
  /** Fixed protocol identifier. Only changes on full protocol replacement. */
  protocol: string
  /** Circuit artifact version. Bump whenever R1CS or trusted setup changes. */
  circuitVersion: string
  /** Target Stellar network. Prevents cross-network replay. */
  network: Network
}

/** Fixed protocol name — matches the value embedded in the circuit. */
export const PROTOCOL_NAME = 'harpocrates'

/** Current circuit version for the Silent Witness circuit. */
export const CIRCUIT_VERSION = '1'

/**
 * Build a DomainDescriptor for the Silent Witness circuit.
 * @param network - target Stellar network
 */
export function buildDomain(network: Network): DomainDescriptor {
  return { protocol: PROTOCOL_NAME, circuitVersion: CIRCUIT_VERSION, network }
}

/**
 * Serialise a DomainDescriptor to its canonical colon-separated string.
 *
 * Format: `harpocrates:1:testnet`
 *
 * This is the same format used to derive the DOMAIN_*_FIELD constants
 * embedded in the Noir circuit.  Keeping it simple (no JSON, no length
 * prefixes) means it can be reproduced verbatim in any language.
 */
export function serialiseDomain(domain: DomainDescriptor): string {
  return `${domain.protocol}:${domain.circuitVersion}:${domain.network}`
}

/**
 * NOTE: The domain_tag field element is computed INSIDE the Noir helper
 * circuit (`silent_witness_helper`), not in JavaScript.  The helper returns
 * `(credential_root, nullifier, domain_tag)` so the browser never needs to
 * call Pedersen independently.
 *
 * This function is provided only for documentation, testing, and off-chain
 * tooling that needs to verify the canonical serialisation string matches
 * the expected circuit inputs.
 */
export function domainString(network: Network): string {
  return serialiseDomain(buildDomain(network))
}
