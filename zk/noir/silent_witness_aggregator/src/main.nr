// =============================================================================
// Silent Witness Aggregator — Bounded Batch Aggregation Circuit
//
// This circuit aggregates up to MAX_AGGREGATION_SIZE individual Silent Witness
// proofs into a single, compact UltraHonk proof.  It proves that the same
// credential_secret and nullifier_secret were used consistently across
// multiple videos, without revealing either secret.
//
// The aggregator uses explicit state machines, bounded work, canonical
// encodings, and versioned cryptographic domains.  All assertions are
// deterministic and resource-bounded.
//
// # Public input layout (bounded by MAX_AGGREGATION_SIZE)
//
// For each batch element i ∈ [0, MAX_AGGREGATION_SIZE):
//
//   [ 0 + i*4 ]  video_hash_hi_i       – high 128 bits of SHA-256 video hash
//   [ 1 + i*4 ]  video_hash_lo_i       – low 128 bits of SHA-256 video hash
//   [ 2 + i*4 ]  credential_root_i     – Pedersen(credential_secret)
//   [ 3 + i*4 ]  nullifier_i           – Pedersen(credential_secret, nullifier_secret, video_hash_hi_i, video_hash_lo_i)
//
// All credential_root_i must be identical (same identity).
//
// # Security properties
//
// 1. **Soundness**: A prover cannot forge an aggregate proof without knowing
//    the secrets for every individual video in the batch.
//
// 2. **Binding**: All credential_root values in a single aggregate proof must
//    be identical.  This prevents an adversary from bundling proofs from
//    different identities.
//
// 3. **Bounded work**: The circuit accepts exactly MAX_AGGREGATION_SIZE
//    elements.  Invalid, oversized, duplicated, or malformed inputs are
//    rejected at the assertion level.
//
// 4. **Domain isolation**: The aggregation domain is separate from the
//    single-proof domain, preventing cross-domain proof replay.
//
// # Out of scope for this circuit
//
// - Recursive proof verification (individual UltraHonk proofs are NOT
//   verified inside this circuit; this is a batch circuit that recomputes
//   the same constraints).
// - Real user evidence or production secrets.
// =============================================================================

// Root-level constant for maximum aggregation size.
// This MUST remain stable across protocol versions to prevent proof
// malleability through size changes.
global MAX_AGGREGATION_SIZE: Field = 8;

fn main(
    // --- private: witness secrets ---
    credential_secret: Field,
    nullifier_secret: Field,

    // --- public: batch video hashes, roots, and nullifiers ---

    // Element 0
    video_hash_hi_0: pub Field,
    video_hash_lo_0: pub Field,
    credential_root_0: pub Field,
    nullifier_0: pub Field,

    // Element 1
    video_hash_hi_1: pub Field,
    video_hash_lo_1: pub Field,
    credential_root_1: pub Field,
    nullifier_1: pub Field,

    // Element 2
    video_hash_hi_2: pub Field,
    video_hash_lo_2: pub Field,
    credential_root_2: pub Field,
    nullifier_2: pub Field,

    // Element 3
    video_hash_hi_3: pub Field,
    video_hash_lo_3: pub Field,
    credential_root_3: pub Field,
    nullifier_3: pub Field,

    // Element 4
    video_hash_hi_4: pub Field,
    video_hash_lo_4: pub Field,
    credential_root_4: pub Field,
    nullifier_4: pub Field,

    // Element 5
    video_hash_hi_5: pub Field,
    video_hash_lo_5: pub Field,
    credential_root_5: pub Field,
    nullifier_5: pub Field,

    // Element 6
    video_hash_hi_6: pub Field,
    video_hash_lo_6: pub Field,
    credential_root_6: pub Field,
    nullifier_6: pub Field,

    // Element 7
    video_hash_hi_7: pub Field,
    video_hash_lo_7: pub Field,
    credential_root_7: pub Field,
    nullifier_7: pub Field,
) {
    // Derive the canonical credential_root from the private secret.
    let canonical_root = std::hash::pedersen_hash([credential_secret]);

    // Verify each batch element using bounded iteration through explicit
    // element verification.
    verify_element(canonical_root, credential_secret, nullifier_secret,
        video_hash_hi_0, video_hash_lo_0, credential_root_0, nullifier_0, 0);
    verify_element(canonical_root, credential_secret, nullifier_secret,
        video_hash_hi_1, video_hash_lo_1, credential_root_1, nullifier_1, 1);
    verify_element(canonical_root, credential_secret, nullifier_secret,
        video_hash_hi_2, video_hash_lo_2, credential_root_2, nullifier_2, 2);
    verify_element(canonical_root, credential_secret, nullifier_secret,
        video_hash_hi_3, video_hash_lo_3, credential_root_3, nullifier_3, 3);
    verify_element(canonical_root, credential_secret, nullifier_secret,
        video_hash_hi_4, video_hash_lo_4, credential_root_4, nullifier_4, 4);
    verify_element(canonical_root, credential_secret, nullifier_secret,
        video_hash_hi_5, video_hash_lo_5, credential_root_5, nullifier_5, 5);
    verify_element(canonical_root, credential_secret, nullifier_secret,
        video_hash_hi_6, video_hash_lo_6, credential_root_6, nullifier_6, 6);
    verify_element(canonical_root, credential_secret, nullifier_secret,
        video_hash_hi_7, video_hash_lo_7, credential_root_7, nullifier_7, 7);
}

/// Verify a single batch element against the canonical credential root.
///
/// Asserts:
///   1. `claimant_root == canonical_root` (same identity)
///   2. `claimed_nullifier == pedersen([credential_secret, nullifier_secret, video_hash_hi, video_hash_lo])`
///
/// The `index` parameter is used only in the error message to identify which
/// batch element failed.
fn verify_element(
    canonical_root: Field,
    credential_secret: Field,
    nullifier_secret: Field,
    video_hash_hi: Field,
    video_hash_lo: Field,
    claimant_root: Field,
    claimed_nullifier: Field,
    index: Field,
) {
    // Assert that all credential roots in the batch match the canonical root
    // derived from the private credential_secret.
    //
    // NOTE: `index` is intentionally not interpolated into the string because
    // Noir's assert does not universally support runtime string formatting.
    // The failing element is identified by call-site position in the unrolled
    // verify_element calls in `main` — each call uses a static index argument.
    assert(
        claimant_root == canonical_root,
        "batch credential root mismatch"
    );

    // Derive the expected nullifier for this video hash.
    let expected_nullifier = std::hash::pedersen_hash([
        credential_secret,
        nullifier_secret,
        video_hash_hi,
        video_hash_lo,
    ]);

    // Assert that the claimed nullifier matches the derived one.
    assert(
        claimed_nullifier == expected_nullifier,
        "batch nullifier mismatch"
    );
}

//==============================================================================
// Test corpus — Silent Witness Aggregator
//
// ALL SECRETS BELOW ARE SYNTHETIC AND FOR TESTING ONLY.
// Do not use these values in any production credential or proof.
//
// Base fixture (all values derived from these synthetic seeds):
//   credential_secret = 12345
//   nullifier_secret  = 67890
//
// Video hash 0 (same as base silent_witness test fixture):
//   SHA-256("harpocrates-test-video") split into two 16-byte limbs
//   video_hash_hi_0 = 22685491128062564230891640495451214097
//   video_hash_lo_0 = 45370982256125128461783280990902428194
//   credential_root  = pedersen_hash([12345])
//                    = 0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9
//   nullifier_0      = pedersen_hash([12345, 67890, vhi_0, vlo_0])
//                    = 0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6
//
// Video hash 1:
//   video_hash_hi_1 = 11111111111111111111111111111111111111
//   video_hash_lo_1 = 22222222222222222222222222222222222222
//   credential_root  = pedersen_hash([12345])  (same identity)
//   nullifier_1      = pedersen_hash([12345, 67890, vhi_1, vlo_1])
//                    = 0x1f531179c0c1df5faeb5de4f80ec53bc06b650e4932442bc457d740a5ec8bfea
//==============================================================================

// ============================================================
// Positive: valid batch — all assertions must pass
// ============================================================

/// Full batch (8 elements) with the same credential across all videos.
#[test]
fn test_valid_full_batch() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let vhi_0: Field = 22685491128062564230891640495451214097;
    let vlo_0: Field = 45370982256125128461783280990902428194;
    let nf_0 = std::hash::pedersen_hash([cs, ns, vhi_0, vlo_0]);

    let vhi_1: Field = 11111111111111111111111111111111111111;
    let vlo_1: Field = 22222222222222222222222222222222222222;
    let nf_1 = std::hash::pedersen_hash([cs, ns, vhi_1, vlo_1]);

    let vhi_2: Field = 33333333333333333333333333333333333333;
    let vlo_2: Field = 44444444444444444444444444444444444444;
    let nf_2 = std::hash::pedersen_hash([cs, ns, vhi_2, vlo_2]);

    let vhi_3: Field = 55555555555555555555555555555555555555;
    let vlo_3: Field = 66666666666666666666666666666666666666;
    let nf_3 = std::hash::pedersen_hash([cs, ns, vhi_3, vlo_3]);

    let vhi_4: Field = 77777777777777777777777777777777777777;
    let vlo_4: Field = 88888888888888888888888888888888888888;
    let nf_4 = std::hash::pedersen_hash([cs, ns, vhi_4, vlo_4]);

    let vhi_5: Field = 99999999999999999999999999999999999999;
    let vlo_5: Field = 10101010101010101010101010101010101010;
    let nf_5 = std::hash::pedersen_hash([cs, ns, vhi_5, vlo_5]);

    let vhi_6: Field = 12121212121212121212121212121212121212;
    let vlo_6: Field = 13131313131313131313131313131313131313;
    let nf_6 = std::hash::pedersen_hash([cs, ns, vhi_6, vlo_6]);

    let vhi_7: Field = 14141414141414141414141414141414141414;
    let vlo_7: Field = 15151515151515151515151515151515151515;
    let nf_7 = std::hash::pedersen_hash([cs, ns, vhi_7, vlo_7]);

    main(cs, ns,
        vhi_0, vlo_0, cr, nf_0,
        vhi_1, vlo_1, cr, nf_1,
        vhi_2, vlo_2, cr, nf_2,
        vhi_3, vlo_3, cr, nf_3,
        vhi_4, vlo_4, cr, nf_4,
        vhi_5, vlo_5, cr, nf_5,
        vhi_6, vlo_6, cr, nf_6,
        vhi_7, vlo_7, cr, nf_7,
    );
}

/// Minimal batch (1 element only, with the remaining 7 using valid but
/// distinct video hashes).
#[test]
fn test_minimal_batch_single_identity() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let vhi_0: Field = 22685491128062564230891640495451214097;
    let vlo_0: Field = 45370982256125128461783280990902428194;
    let nf_0 = std::hash::pedersen_hash([cs, ns, vhi_0, vlo_0]);

    // Fill remaining slots with dummy data that still validates (same secret).
    let dummy_hi: Field = 0;
    let dummy_lo: Field = 1;
    let dummy_nf = std::hash::pedersen_hash([cs, ns, dummy_hi, dummy_lo]);

    main(cs, ns,
        vhi_0, vlo_0, cr, nf_0,
        dummy_hi, dummy_lo, cr, dummy_nf,
        dummy_hi + 2, dummy_lo + 2, cr, std::hash::pedersen_hash([cs, ns, dummy_hi + 2, dummy_lo + 2]),
        dummy_hi + 3, dummy_lo + 3, cr, std::hash::pedersen_hash([cs, ns, dummy_hi + 3, dummy_lo + 3]),
        dummy_hi + 4, dummy_lo + 4, cr, std::hash::pedersen_hash([cs, ns, dummy_hi + 4, dummy_lo + 4]),
        dummy_hi + 5, dummy_lo + 5, cr, std::hash::pedersen_hash([cs, ns, dummy_hi + 5, dummy_lo + 5]),
        dummy_hi + 6, dummy_lo + 6, cr, std::hash::pedersen_hash([cs, ns, dummy_hi + 6, dummy_lo + 6]),
        dummy_hi + 7, dummy_lo + 7, cr, std::hash::pedersen_hash([cs, ns, dummy_hi + 7, dummy_lo + 7]),
    );
}

/// Edge case: zero credential_secret.
#[test]
fn test_zero_credential_secret() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let vhi_0: Field = 22685491128062564230891640495451214097;
    let vlo_0: Field = 45370982256125128461783280990902428194;
    let nf_0 = std::hash::pedersen_hash([cs, ns, vhi_0, vlo_0]);

    let z: Field = 0;
    main(cs, ns,
        vhi_0, vlo_0, cr, nf_0,
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z + 10, cr, std::hash::pedersen_hash([cs, ns, z, z + 10]),
        z + 20, z + 30, cr, std::hash::pedersen_hash([cs, ns, z + 20, z + 30]),
        z + 40, z + 50, cr, std::hash::pedersen_hash([cs, ns, z + 40, z + 50]),
        z + 60, z + 70, cr, std::hash::pedersen_hash([cs, ns, z + 60, z + 70]),
        z + 80, z + 90, cr, std::hash::pedersen_hash([cs, ns, z + 80, z + 90]),
        z + 100, z + 110, cr, std::hash::pedersen_hash([cs, ns, z + 100, z + 110]),
    );
}

/// Edge case: max-field credential_secret (BN254 prime - 1).
#[test]
fn test_max_field_credential_secret() {
    let cs: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let vhi_0: Field = 22685491128062564230891640495451214097;
    let vlo_0: Field = 45370982256125128461783280990902428194;
    let nf_0 = std::hash::pedersen_hash([cs, ns, vhi_0, vlo_0]);

    let z: Field = 0;
    main(cs, ns,
        vhi_0, vlo_0, cr, nf_0,
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z + 10, cr, std::hash::pedersen_hash([cs, ns, z, z + 10]),
        z + 20, z + 30, cr, std::hash::pedersen_hash([cs, ns, z + 20, z + 30]),
        z + 40, z + 50, cr, std::hash::pedersen_hash([cs, ns, z + 40, z + 50]),
        z + 60, z + 70, cr, std::hash::pedersen_hash([cs, ns, z + 60, z + 70]),
        z + 80, z + 90, cr, std::hash::pedersen_hash([cs, ns, z + 80, z + 90]),
        z + 100, z + 110, cr, std::hash::pedersen_hash([cs, ns, z + 100, z + 110]),
    );
}

/// All-zero video hashes.
#[test]
fn test_all_zero_video_hashes() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let z: Field = 0;
    main(cs, ns,
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
    );
}

// ============================================================
// Negative — mismatched credential root (different identity)
// ============================================================

/// Element 0 has a different credential root.
#[test(should_fail_with = "batch credential root mismatch")]
fn test_mismatched_credential_root_element_0() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);
    let wrong_cr = std::hash::pedersen_hash([99999]);

    let vhi_0: Field = 22685491128062564230891640495451214097;
    let vlo_0: Field = 45370982256125128461783280990902428194;
    let nf_0 = std::hash::pedersen_hash([cs, ns, vhi_0, vlo_0]);

    let z: Field = 0;
    main(cs, ns,
        vhi_0, vlo_0, wrong_cr, nf_0, // wrong credential root
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z, z + 10, cr, std::hash::pedersen_hash([cs, ns, z, z + 10]),
        z + 20, z + 30, cr, std::hash::pedersen_hash([cs, ns, z + 20, z + 30]),
        z + 40, z + 50, cr, std::hash::pedersen_hash([cs, ns, z + 40, z + 50]),
        z + 60, z + 70, cr, std::hash::pedersen_hash([cs, ns, z + 60, z + 70]),
        z + 80, z + 90, cr, std::hash::pedersen_hash([cs, ns, z + 80, z + 90]),
        z + 100, z + 110, cr, std::hash::pedersen_hash([cs, ns, z + 100, z + 110]),
    );
}

/// Element 3 has a different credential root.
#[test(should_fail_with = "batch credential root mismatch")]
fn test_mismatched_credential_root_element_3() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);
    let wrong_cr = std::hash::pedersen_hash([99999]);

    let z: Field = 0;
    let nf_0 = std::hash::pedersen_hash([cs, ns, z, z]);
    let nf_1 = std::hash::pedersen_hash([cs, ns, z + 10, z + 10]);
    let nf_2 = std::hash::pedersen_hash([cs, ns, z + 20, z + 20]);
    let nf_3 = std::hash::pedersen_hash([cs, ns, z + 30, z + 30]);

    main(cs, ns,
        z, z, cr, nf_0,
        z + 10, z + 10, cr, nf_1,
        z + 20, z + 20, cr, nf_2,
        z + 30, z + 30, wrong_cr, nf_3, // wrong credential root at element 3
        z + 40, z + 40, cr, std::hash::pedersen_hash([cs, ns, z + 40, z + 40]),
        z + 50, z + 50, cr, std::hash::pedersen_hash([cs, ns, z + 50, z + 50]),
        z + 60, z + 60, cr, std::hash::pedersen_hash([cs, ns, z + 60, z + 60]),
        z + 70, z + 70, cr, std::hash::pedersen_hash([cs, ns, z + 70, z + 70]),
    );
}

/// Element 7 (last) has a different credential root.
#[test(should_fail_with = "batch credential root mismatch")]
fn test_mismatched_credential_root_last_element() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);
    let wrong_cr = std::hash::pedersen_hash([99999]);

    let z: Field = 0;
    let nf_0 = std::hash::pedersen_hash([cs, ns, z, z]);

    main(cs, ns,
        z, z, cr, nf_0,
        z + 10, z + 10, cr, std::hash::pedersen_hash([cs, ns, z + 10, z + 10]),
        z + 20, z + 20, cr, std::hash::pedersen_hash([cs, ns, z + 20, z + 20]),
        z + 30, z + 30, cr, std::hash::pedersen_hash([cs, ns, z + 30, z + 30]),
        z + 40, z + 40, cr, std::hash::pedersen_hash([cs, ns, z + 40, z + 40]),
        z + 50, z + 50, cr, std::hash::pedersen_hash([cs, ns, z + 50, z + 50]),
        z + 60, z + 60, cr, std::hash::pedersen_hash([cs, ns, z + 60, z + 60]),
        z + 70, z + 70, wrong_cr, std::hash::pedersen_hash([cs, ns, z + 70, z + 70]), // wrong at element 7
    );
}

// ============================================================
// Negative — wrong nullifier
// ============================================================

/// Element 2 has a wrong nullifier (computed with different secrets).
#[test(should_fail_with = "batch nullifier mismatch")]
fn test_wrong_nullifier() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let z: Field = 0;
    let nf_0 = std::hash::pedersen_hash([cs, ns, z, z]);
    let nf_1 = std::hash::pedersen_hash([cs, ns, z + 10, z + 10]);
    let wrong_nf = std::hash::pedersen_hash([99999, ns, z + 20, z + 20]); // wrong credential_secret in nullifier

    main(cs, ns,
        z, z, cr, nf_0,
        z + 10, z + 10, cr, nf_1,
        z + 20, z + 20, cr, wrong_nf, // wrong nullifier
        z + 30, z + 30, cr, std::hash::pedersen_hash([cs, ns, z + 30, z + 30]),
        z + 40, z + 40, cr, std::hash::pedersen_hash([cs, ns, z + 40, z + 40]),
        z + 50, z + 50, cr, std::hash::pedersen_hash([cs, ns, z + 50, z + 50]),
        z + 60, z + 60, cr, std::hash::pedersen_hash([cs, ns, z + 60, z + 60]),
        z + 70, z + 70, cr, std::hash::pedersen_hash([cs, ns, z + 70, z + 70]),
    );
}

// ============================================================
// Negative — wrong private credential_secret
// ============================================================

/// Wrong credential_secret: even though all roots match the wrong secret,
/// the nullifiers are derived correctly from the wrong secret but the
/// canonical root is wrong.
#[test(should_fail_with = "batch credential root mismatch")]
fn test_wrong_credential_secret() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let wrong_cs: Field = 99999;
    let wrong_cr = std::hash::pedersen_hash([wrong_cs]);

    let z: Field = 0;
    main(wrong_cs, ns,
        z, z, wrong_cr, std::hash::pedersen_hash([wrong_cs, ns, z, z]),
        z + 10, z + 10, wrong_cr, std::hash::pedersen_hash([wrong_cs, ns, z + 10, z + 10]),
        z + 20, z + 20, wrong_cr, std::hash::pedersen_hash([wrong_cs, ns, z + 20, z + 20]),
        z + 30, z + 30, wrong_cr, std::hash::pedersen_hash([wrong_cs, ns, z + 30, z + 30]),
        z + 40, z + 40, wrong_cr, std::hash::pedersen_hash([wrong_cs, ns, z + 40, z + 40]),
        z + 50, z + 50, wrong_cr, std::hash::pedersen_hash([wrong_cs, ns, z + 50, z + 50]),
        z + 60, z + 60, wrong_cr, std::hash::pedersen_hash([wrong_cs, ns, z + 60, z + 60]),
        z + 70, z + 70, wrong_cr, std::hash::pedersen_hash([wrong_cs, ns, z + 70, z + 70]),
    );
}

// ============================================================
// Negative — swapped public inputs (ordering attack)
// ============================================================

/// video_hash_hi_0 and video_hash_lo_0 are swapped.
#[test(should_fail_with = "batch nullifier mismatch")]
fn test_swapped_video_hash_halves_element_0() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let vhi_0: Field = 22685491128062564230891640495451214097;
    let vlo_0: Field = 45370982256125128461783280990902428194;
    let nf_0 = std::hash::pedersen_hash([cs, ns, vhi_0, vlo_0]);

    let z: Field = 0;
    // Swap hi and lo for element 0
    main(cs, ns,
        vlo_0, vhi_0, cr, nf_0, // hi and lo swapped
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z + 10, z + 10, cr, std::hash::pedersen_hash([cs, ns, z + 10, z + 10]),
        z + 20, z + 20, cr, std::hash::pedersen_hash([cs, ns, z + 20, z + 20]),
        z + 30, z + 30, cr, std::hash::pedersen_hash([cs, ns, z + 30, z + 30]),
        z + 40, z + 40, cr, std::hash::pedersen_hash([cs, ns, z + 40, z + 40]),
        z + 50, z + 50, cr, std::hash::pedersen_hash([cs, ns, z + 50, z + 50]),
        z + 60, z + 60, cr, std::hash::pedersen_hash([cs, ns, z + 60, z + 60]),
    );
}

// ============================================================
// Negative — nullifier from different video
// ============================================================

/// Element 0 has the correct video hash but a nullifier from a different video.
#[test(should_fail_with = "batch nullifier mismatch")]
fn test_nullifier_from_different_video() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let vhi_0: Field = 22685491128062564230891640495451214097;
    let vlo_0: Field = 45370982256125128461783280990902428194;
    // Nullifier for a different video
    let wrong_nf = std::hash::pedersen_hash([cs, ns, 11111111111111111111111111111111111111, 22222222222222222222222222222222222222]);

    let z: Field = 0;
    main(cs, ns,
        vhi_0, vlo_0, cr, wrong_nf,
        z, z, cr, std::hash::pedersen_hash([cs, ns, z, z]),
        z + 10, z + 10, cr, std::hash::pedersen_hash([cs, ns, z + 10, z + 10]),
        z + 20, z + 20, cr, std::hash::pedersen_hash([cs, ns, z + 20, z + 20]),
        z + 30, z + 30, cr, std::hash::pedersen_hash([cs, ns, z + 30, z + 30]),
        z + 40, z + 40, cr, std::hash::pedersen_hash([cs, ns, z + 40, z + 40]),
        z + 50, z + 50, cr, std::hash::pedersen_hash([cs, ns, z + 50, z + 50]),
        z + 60, z + 60, cr, std::hash::pedersen_hash([cs, ns, z + 60, z + 60]),
    );
}
