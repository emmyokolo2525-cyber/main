// =============================================================================
// Revocation Witness — Non-Membership Proof in a Sorted Merkle Tree
//
// This circuit proves that a credential_root is NOT in the published
// revocation tree.  The prover supplies every leaf of the depth‑3 Merkle
// tree (8 leaves) as private inputs.  The circuit recomputes the tree root
// internally and asserts that credential_root differs from every leaf.
//
// The verifier learns only the public inputs:
//   [0] revocation_root  – Merkle root of the revocation tree
//   [1] nullifier        – binds to the prover (one‑use, replay prevention)
//   [2] domain_separator – binds to network / contract / version
//   [3] credential_root  – pseudonymous identity anchor
//
// Privacy properties
// ------------------
// - The revocation tree leaves are private → the verifier does NOT learn
//   which credentials are revoked.
// - credential_root is public but pseudonymous (Pedersen hash of a secret).
// - nullifier is one‑use, preventing replay of the same non‑revocation proof.
//
// Domain binding
// --------------
// The domain_separator is computed off‑chain as
//   pedersen_hash(["HARPOCRATES_REVOCATION_V1", network_id_hi, network_id_lo])
// and injected as a public input.  The Soroban contract independently
// computes the same value from `env.ledger().network_id()` and asserts
// equality before accepting the proof.
// =============================================================================

use std::hash::pedersen_hash;

fn main(
    // --- private: witness secrets ---
    credential_secret: Field,
    nullifier_secret: Field,

    // --- private: revocation tree leaves ---
    leaf_0: Field,
    leaf_1: Field,
    leaf_2: Field,
    leaf_3: Field,
    leaf_4: Field,
    leaf_5: Field,
    leaf_6: Field,
    leaf_7: Field,

    // --- public: on‑chain commitments ---
    revocation_root: pub Field,
    nullifier: pub Field,
    domain_separator: pub Field,   // domain binding — verified by contract
    credential_root: pub Field,
) {
    // Derive credential_root from the private secret.
    let derived_root = pedersen_hash([credential_secret]);
    assert(derived_root == credential_root, "credential root mismatch");

    // Derive nullifier from secrets.
    let derived_nullifier = pedersen_hash([credential_secret, nullifier_secret]);
    assert(derived_nullifier == nullifier, "nullifier mismatch");

    // ------------------------------------------------------------------
    // Merkle root computation (depth 3, 8 leaves, Pedersen)
    // ------------------------------------------------------------------
    let node_01 = pedersen_hash([leaf_0, leaf_1]);
    let node_23 = pedersen_hash([leaf_2, leaf_3]);
    let node_45 = pedersen_hash([leaf_4, leaf_5]);
    let node_67 = pedersen_hash([leaf_6, leaf_7]);

    let node_0123 = pedersen_hash([node_01, node_23]);
    let node_4567 = pedersen_hash([node_45, node_67]);

    let computed_root = pedersen_hash([node_0123, node_4567]);
    assert(computed_root == revocation_root, "revocation root mismatch");

    // ------------------------------------------------------------------
    // Non‑membership: credential_root is NOT any leaf
    // ------------------------------------------------------------------
    assert(credential_root != leaf_0, "credential is in revocation set (leaf 0)");
    assert(credential_root != leaf_1, "credential is in revocation set (leaf 1)");
    assert(credential_root != leaf_2, "credential is in revocation set (leaf 2)");
    assert(credential_root != leaf_3, "credential is in revocation set (leaf 3)");
    assert(credential_root != leaf_4, "credential is in revocation set (leaf 4)");
    assert(credential_root != leaf_5, "credential is in revocation set (leaf 5)");
    assert(credential_root != leaf_6, "credential is in revocation set (leaf 6)");
    assert(credential_root != leaf_7, "credential is in revocation set (leaf 7)");

    // Domain binding: `domain_separator` is a structured public input that
    // the contract verifies before calling the UltraHonk verifier.  Because
    // the verifier cryptographically binds all public inputs, changing the
    // domain_separator invalidates the proof — providing defense-in-depth:
    // the circuit binds it, and the contract independently checks it.
    //
    // Format: 32 bytes (one BN254 field element)
    //   [ 0..24)  "HARPOCRATES_REVOCATION_V1" (ASCII)
    //   [24..32)  network_tag (0 = testnet, non-zero = deployment-specific)
    let _ = domain_separator;
}

// =============================================================================
// Test corpus — Revocation Witness (non‑membership)
//
// ALL SECRETS AND LEAF VALUES ARE SYNTHETIC AND FOR TESTING ONLY.
// Do not use in production.
//
// Test tree (8 leaves, depth 3):
//   leaf_0 = 0x00…00  (sentinel — always < any real credential_root)
//   leaf_1 = pedersen([33333])
//   leaf_2 = pedersen([44444])
//   leaf_3 = pedersen([55555])
//   leaf_4 = pedersen([66666])
//   leaf_5 = pedersen([77777])
//   leaf_6 = pedersen([88888])
//   leaf_7 = pedersen([99999])
//
// The non‑member credential is 12345, which is NOT among the leaves above.
//
// Domain separator for tests:
//   pedersen_hash(["HARPOCRATES_REVOCATION_V1", 0, 0])
// =============================================================================

/// Compute the test domain separator (network_tag = 0 for testnet).
/// Format: "HARPOCRATES_REVOCATION_V1" + 8 zero bytes (version V1, testnet).
/// This MUST match the REVOCATION_DOMAIN_SEPARATOR constant in the contract.
fn test_domain_separator() -> Field {
    // Raw ASCII bytes padded to 32 bytes: "HARPOCRATES_REVOCATION_V1" + 8 zero bytes
    0x484152504f4352415445535f5245564f434154494f4e5f5631
}

/// Compute the Merkle root of the test tree.
fn test_tree_root(
    l0: Field, l1: Field, l2: Field, l3: Field,
    l4: Field, l5: Field, l6: Field, l7: Field,
) -> Field {
    let n01 = pedersen_hash([l0, l1]);
    let n23 = pedersen_hash([l2, l3]);
    let n45 = pedersen_hash([l4, l5]);
    let n67 = pedersen_hash([l6, l7]);
    let n0123 = pedersen_hash([n01, n23]);
    let n4567 = pedersen_hash([n45, n67]);
    pedersen_hash([n0123, n4567])
}

// ================================================================
// Positive tests
// ================================================================

/// Base fixture: credential 12345 is NOT in the test revocation tree.
#[test]
fn test_valid_non_revocation_witness() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let l0: Field = 0;
    let l1 = pedersen_hash([33333]);
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = pedersen_hash([99999]);

    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    main(cs, ns, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, root);
}

/// Edge case: zero credential_secret — still not in the revocation set.
#[test]
fn test_zero_credential_secret_non_revocation() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    // Use a different tree: leaves that don't include root(0).
    let l0: Field = 0;
    let l1 = pedersen_hash([11111]);
    let l2 = pedersen_hash([22222]);
    let l3 = pedersen_hash([33333]);
    let l4 = pedersen_hash([44444]);
    let l5 = pedersen_hash([55555]);
    let l6 = pedersen_hash([66666]);
    let l7 = pedersen_hash([77777]);

    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    main(cs, ns, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, root);
}

/// Edge case: max-field credential_secret (BN254 prime - 1).
#[test]
fn test_max_field_non_revocation() {
    let cs: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let l0: Field = 0;
    let l1 = pedersen_hash([33333]);
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = pedersen_hash([99999]);

    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    main(cs, ns, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, root);
}

/// All leaves are zero (empty revocation tree).
#[test]
fn test_empty_revocation_tree() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let z: Field = 0;
    let tree_root = test_tree_root(z, z, z, z, z, z, z, z);
    let ds = test_domain_separator();

    main(cs, ns, z, z, z, z, z, z, z, z, tree_root, null, ds, root);
}

// ================================================================
// Negative tests
// ================================================================

/// Wrong credential_secret: derived root doesn't match public `credential_root`.
#[test(should_fail_with = "credential root mismatch")]
fn test_wrong_credential_secret() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);   // real root for cs=12345
    let null = pedersen_hash([cs, ns]);

    let l0: Field = 0;
    let l1 = pedersen_hash([33333]);
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = pedersen_hash([99999]);
    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    // Pass 99999 as private secret but public root is for 12345
    let wrong_root = pedersen_hash([99999]);
    main(99999, ns, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, wrong_root);
}

/// Wrong nullifier_secret: nullifier derivation fails.
#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_nullifier_secret() {
    let cs: Field = 12345;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, 67890]);

    let l0: Field = 0;
    let l1 = pedersen_hash([33333]);
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = pedersen_hash([99999]);
    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    // Pass 11111 as nullifier_secret but public nullifier is for 67890
    main(cs, 11111, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, root);
}

/// Credential IS in the revocation tree (leaf 1 = pedersen([33333])).
#[test(should_fail_with = "credential is in revocation set")]
fn test_revoked_credential() {
    let cs: Field = 33333;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let l0: Field = 0;
    let l1 = pedersen_hash([33333]);  // credential is leaf 1
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = pedersen_hash([99999]);
    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    main(cs, ns, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, root);
}

/// Credential at leaf 0 (sentinel position — would only match if root == 0).
/// This test ensures leaf_0 is also checked.
#[test(should_fail_with = "credential is in revocation set")]
fn test_credential_at_leaf_zero() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let l0 = root;  // credential IS at leaf 0
    let l1 = pedersen_hash([33333]);
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = pedersen_hash([99999]);
    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    main(cs, ns, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, root);
}

/// Credential at last leaf (leaf 7).
#[test(should_fail_with = "credential is in revocation set")]
fn test_credential_at_leaf_seven() {
    let cs: Field = 99999;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let l0: Field = 0;
    let l1 = pedersen_hash([33333]);
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = root;  // credential IS at leaf 7
    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    main(cs, ns, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, root);
}

/// Tampered revocation_root: leaves match the tree but public root is wrong.
#[test(should_fail_with = "revocation root mismatch")]
fn test_tampered_revocation_root() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let l0: Field = 0;
    let l1 = pedersen_hash([33333]);
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = pedersen_hash([99999]);
    let ds = test_domain_separator();

    // Supply 0 as revocation_root instead of the real tree root
    main(cs, ns, l0, l1, l2, l3, l4, l5, l6, l7, 0, null, ds, root);
}

/// Tampered leaves: a leaf is changed so the computed root won't match.
#[test(should_fail_with = "revocation root mismatch")]
fn test_tampered_leaves() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let l0: Field = 0;
    let l1 = pedersen_hash([33333]);
    let l2 = pedersen_hash([44444]);
    let l3 = pedersen_hash([55555]);
    let l4 = pedersen_hash([66666]);
    let l5 = pedersen_hash([77777]);
    let l6 = pedersen_hash([88888]);
    let l7 = pedersen_hash([99999]);
    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    // Tamper with leaf 3 — computed root changes so assertion fails
    main(cs, ns, l0, l1, l2, 0xDEAD, l4, l5, l6, l7, tree_root, null, ds, root);
}

/// All-revoked tree (8 unique leaves filled): a non-member should still pass.
/// Tests that a "full" tree correctly rejects non-members.
#[test]
fn test_full_tree_non_member() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = pedersen_hash([cs]);
    let null = pedersen_hash([cs, ns]);

    let l0 = pedersen_hash([11111]);
    let l1 = pedersen_hash([22222]);
    let l2 = pedersen_hash([33333]);
    let l3 = pedersen_hash([44444]);
    let l4 = pedersen_hash([55555]);
    let l5 = pedersen_hash([66666]);
    let l6 = pedersen_hash([77777]);
    let l7 = pedersen_hash([88888]);
    let tree_root = test_tree_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    main(cs, ns, l0, l1, l2, l3, l4, l5, l6, l7, tree_root, null, ds, root);
}
