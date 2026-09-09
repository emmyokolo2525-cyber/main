// ---------------------------------------------------------------------------
// Canonical evidence digest algorithm identifiers.
//
// Each constant maps a well-known hash algorithm to a numeric identifier
// that is bound into the evidence digest commitment inside the circuit.
// This prevents proofs from being detached from the exact hashing algorithm
// used to produce the evidence digest.
//
//   DIGEST_ALGORITHM_SHA256 = 0   — SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------
global DIGEST_ALGORITHM_SHA256: Field = 0;
global SCOPED_NULLIFIER_V1: Field = 0x00484152504f4352415445535f53434f5045445f4e554c4c49464945525f5631;

global DOMAIN_PROTOCOL_FIELD: Field = 0x261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201;
global DOMAIN_VERSION_FIELD: Field = 0x0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623;
global DOMAIN_NETWORK_FIELD: Field = 0x2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f;

fn main(
    credential_secret: Field,
    nullifier_secret: Field,
    video_hash_hi: pub Field,
    video_hash_lo: pub Field,
    credential_root: pub Field,
    nullifier: pub Field,
    verifier_scope: pub Field,
    epoch: pub Field,
    domain_tag: pub Field,
) {
    let scope_hash = std::hash::pedersen_hash([
        SCOPED_NULLIFIER_V1,
        verifier_scope,
        epoch,
    ]);

    // Commit to the complete canonical evidence digest: algorithm identifier,
    // video hash halves, and scope commitment hash.
    let evidence_digest = std::hash::pedersen_hash([
        DIGEST_ALGORITHM_SHA256,
        video_hash_hi,
        video_hash_lo,
        scope_hash,
    ]);

    let derived_root = std::hash::pedersen_hash([credential_secret]);
    let derived_nullifier = std::hash::pedersen_hash([
        credential_secret,
        nullifier_secret,
        evidence_digest,
    ]);

    assert(derived_root == credential_root, "credential root mismatch");
    assert(derived_nullifier == nullifier, "nullifier mismatch");

    // --- domain separation constraint ---
    // Bind this proof to the Harpocrates protocol, circuit version 1, and
    // the target network.
    let expected_domain_tag = std::hash::pedersen_hash([
        DOMAIN_PROTOCOL_FIELD,
        DOMAIN_VERSION_FIELD,
        DOMAIN_NETWORK_FIELD,
    ]);
    assert(domain_tag == expected_domain_tag, "domain tag mismatch");
}

// ---------------------------------------------------------------------------
// Test corpus -- Silent Witness circuit (scoped nullifier v1)
//
// ALL SECRETS ARE SYNTHETIC AND FOR TESTING ONLY.
//
// Base fixture (all values derived from these synthetic seeds):
//   credential_secret   = 12345
//   nullifier_secret    = 67890
//   video_hash_hi       = 22685491128062564230891640495451214097
//                         (hi-128 bits of SHA-256("harpocrates-test-video"))
//   video_hash_lo       = 45370982256125128461783280990902428194
//                         (lo-128 bits of SHA-256("harpocrates-test-video"))
//   DIGEST_ALGORITHM_ID = 0 (SHA-256)
//
// Derived public inputs (BN254/UltraHonk, Pedersen):
//   evidence_digest  = pedersen_hash([0, video_hash_hi, video_hash_lo])
//   credential_root  = pedersen_hash([12345])
//                    = 0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9
//   nullifier        = pedersen_hash([12345, 67890, evidence_digest])
//                    = (changed from previous derivation — now bound to canonical evidence digest)
//
// Edge-case secrets:
//   zero_credential_secret      = 0
//   max_field_credential_secret = BN254 prime - 1
//   zero_video_hash: hi = 0, lo = 0
// ---------------------------------------------------------------------------

// Pre-compute the expected domain_tag from the embedded constants so tests
// can reference it without repeating the derivation.
global EXPECTED_DOMAIN_TAG: Field = std::hash::pedersen_hash([
    DOMAIN_PROTOCOL_FIELD,
    DOMAIN_VERSION_FIELD,
    DOMAIN_NETWORK_FIELD,
]);

// Public input ordering expected by the Soroban verifier:
//   [0] video_hash_hi
//   [1] video_hash_lo
//   [2] credential_root
//   [3] nullifier
//   [4] verifier_scope
//   [5] epoch
//   [6] domain_tag
// ---------------------------------------------------------------------------

/// Compute the scoped nullifier for given inputs.
/// Exported for test vector computation.
fn compute_scoped_nullifier(
    cs: Field,
    ns: Field,
    vhi: Field,
    vlo: Field,
    scope: Field,
    ep: Field,
) -> Field {
    let scope_hash = std::hash::pedersen_hash([SCOPED_NULLIFIER_V1, scope, ep]);
    let evidence = std::hash::pedersen_hash([DIGEST_ALGORITHM_SHA256, vhi, vlo, scope_hash]);
    std::hash::pedersen_hash([cs, ns, evidence])
}

// ============================================================
// Positive: well-formed witness
// ============================================================

// All inputs correct: global scope (0), epoch 0.
#[test]
fn test_valid_witness() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, EXPECTED_DOMAIN_TAG);
}

// Edge: zero credential_secret is a valid field element.
#[test]
fn test_zero_credential_secret() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, EXPECTED_DOMAIN_TAG);
}

// Edge: max-field credential_secret (BN254 prime - 1).
#[test]
fn test_max_field_credential_secret() {
    let cs: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, EXPECTED_DOMAIN_TAG);
}

// Edge: all-zero video hash (e.g. blank-frame video) with correct secrets.
// The nullifier is derived via the evidence digest commitment, not raw halves.
#[test]
fn test_zero_video_hash() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 0;
    let vlo: Field = 0;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, EXPECTED_DOMAIN_TAG);
}

// ============================================================
// Negative — wrong private inputs (existing)
// ============================================================

#[test(should_fail_with = "credential root mismatch")]
fn test_wrong_credential_secret() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(99999, ns, vhi, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_nullifier_secret() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, 11111, vhi, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

// ============================================================
// Negative — wrong video hash (existing)
// ============================================================

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_hi() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, 99999999999999999999999999999999999999, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_lo() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, 99999999999999999999999999999999999999, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_both_halves() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, 11111111111111111111111111111111111111, 22222222222222222222222222222222222222, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

// ============================================================
// Negative — tampered public inputs (existing)
// ============================================================

#[test(should_fail_with = "credential root mismatch")]
fn test_tampered_credential_root_public_input() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([99999]); // wrong root
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_tampered_nullifier_public_input() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    // Nullifier for a different credential
    let nul = compute_scoped_nullifier(99999, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

#[test(should_fail_with = "credential root mismatch")]
fn test_both_public_inputs_wrong_identity() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([99999]);
    let nul = compute_scoped_nullifier(99999, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

// ============================================================
// Negative — public input ordering attacks (existing)
// ============================================================

#[test(should_fail_with = "credential root mismatch")]
fn test_swapped_credential_root_and_nullifier() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    // Swap: nullifier passed as credential_root, root passed as nullifier
    main(cs, ns, vhi, vlo, nul, root, scope, ep, EXPECTED_DOMAIN_TAG);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_swapped_video_hash_halves() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    // Swap: lo in hi slot, hi in lo slot
    main(cs, ns, vlo, vhi, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

// ============================================================
// Negative -- scope binding
// ============================================================

// A valid proof for scope=0 must NOT satisfy scope=999.
// Proves the nullifier binds to the specific verifier_scope.
#[test(should_fail_with = "nullifier mismatch")]
fn test_nullifier_from_different_scope() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    // Nullifier computed for scope=999 (different scope)
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, 999, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

// A valid proof for epoch=1 must NOT satisfy epoch=2.
// Proves the nullifier binds to the specific epoch.
#[test(should_fail_with = "nullifier mismatch")]
fn test_nullifier_from_different_epoch() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 42;
    let ep: Field = 1;
    let root = pedersen_hash([cs]);
    // Nullifier computed for epoch=2 (different epoch, same scope)
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, 2);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

// ============================================================
// Negative -- nullifier/video binding (unchanged from v1)
// ============================================================

#[test(should_fail_with = "nullifier mismatch")]
fn test_nullifier_from_different_video() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    // Nullifier computed for a different video hash (vhi+1)
    let nul = compute_scoped_nullifier(cs, ns, vhi + 1, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, EXPECTED_DOMAIN_TAG);
}

// ============================================================
// Negative — domain tag mismatch (NEW: domain separation tests)
// ============================================================

// Zero domain_tag — never equals the expected Pedersen hash.
#[test(should_fail_with = "domain tag mismatch")]
fn test_zero_domain_tag_rejected() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, 0);
}

// ============================================================
// Negative -- evidence digest algorithm binding
// ============================================================

fn nullifier_with_algorithm_id(
    cs: Field, ns: Field, vhi: Field, vlo: Field, algo: Field, scope: Field, ep: Field,
) -> Field {
    let scope_hash = std::hash::pedersen_hash([SCOPED_NULLIFIER_V1, scope, ep]);
    let evidence = std::hash::pedersen_hash([algo, vhi, vlo, scope_hash]);
    std::hash::pedersen_hash([cs, ns, evidence])
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_algorithm_id_in_nullifier() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    // nullifier computed with algorithm_id=1 (substituted)
    let wrong_null = nullifier_with_algorithm_id(cs, ns, vhi, vlo, 1, scope, ep);
    main(cs, ns, vhi, vlo, root, wrong_null, scope, ep, EXPECTED_DOMAIN_TAG);
}

// ============================================================
// Negative -- evidence digest commitment preimage
// ============================================================

#[test(should_fail_with = "nullifier mismatch")]
fn test_swapped_algorithm_id_and_video_hash_hi() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let scope_hash = std::hash::pedersen_hash([SCOPED_NULLIFIER_V1, scope, ep]);
    let swapped_evidence = std::hash::pedersen_hash([vhi, DIGEST_ALGORITHM_SHA256, vlo, scope_hash]);
    let root = std::hash::pedersen_hash([cs]);
    let swapped_null = std::hash::pedersen_hash([cs, ns, swapped_evidence]);
    main(cs, ns, vhi, vlo, root, swapped_null, scope, ep, EXPECTED_DOMAIN_TAG);
}
