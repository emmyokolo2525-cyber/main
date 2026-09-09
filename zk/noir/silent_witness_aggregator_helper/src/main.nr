// =============================================================================
// Silent Witness Aggregator Helper
//
// Derives batch public inputs (credential_root, nullifier) for all elements
// in a bounded aggregation batch from the private secrets and video hashes.
//
// This mirrors the role of `silent_witness_helper` for the aggregation flow.
//
// The output is suitable for feeding into the `silent_witness_aggregator`
// circuit's Prover.toml and for constructing on-chain public inputs.
//
// # Output
//
// For each batch element i (i = 0..MAX_AGGREGATION_SIZE-1):
//   credential_root_i  – Pedersen(credential_secret)
//   nullifier_i        – Pedersen(credential_secret, nullifier_secret, video_hash_hi_i, video_hash_lo_i)
//
// All credential_root outputs are identical (same identity).
// =============================================================================

global MAX_AGGREGATION_SIZE: Field = 8;

fn main(
    credential_secret: Field,
    nullifier_secret: Field,

    // Video hashes for each batch element
    video_hash_hi_0: Field,
    video_hash_lo_0: Field,
    video_hash_hi_1: Field,
    video_hash_lo_1: Field,
    video_hash_hi_2: Field,
    video_hash_lo_2: Field,
    video_hash_hi_3: Field,
    video_hash_lo_3: Field,
    video_hash_hi_4: Field,
    video_hash_lo_4: Field,
    video_hash_hi_5: Field,
    video_hash_lo_5: Field,
    video_hash_hi_6: Field,
    video_hash_lo_6: Field,
    video_hash_hi_7: Field,
    video_hash_lo_7: Field,
) -> pub [
    (Field, Field), // (credential_root, nullifier) for element 0
    (Field, Field), // element 1
    (Field, Field), // element 2
    (Field, Field), // element 3
    (Field, Field), // element 4
    (Field, Field), // element 5
    (Field, Field), // element 6
    (Field, Field), // element 7
] {
    let canonical_root = std::hash::pedersen_hash([credential_secret]);

    let nullifier_0 = std::hash::pedersen_hash([credential_secret, nullifier_secret, video_hash_hi_0, video_hash_lo_0]);
    let nullifier_1 = std::hash::pedersen_hash([credential_secret, nullifier_secret, video_hash_hi_1, video_hash_lo_1]);
    let nullifier_2 = std::hash::pedersen_hash([credential_secret, nullifier_secret, video_hash_hi_2, video_hash_lo_2]);
    let nullifier_3 = std::hash::pedersen_hash([credential_secret, nullifier_secret, video_hash_hi_3, video_hash_lo_3]);
    let nullifier_4 = std::hash::pedersen_hash([credential_secret, nullifier_secret, video_hash_hi_4, video_hash_lo_4]);
    let nullifier_5 = std::hash::pedersen_hash([credential_secret, nullifier_secret, video_hash_hi_5, video_hash_lo_5]);
    let nullifier_6 = std::hash::pedersen_hash([credential_secret, nullifier_secret, video_hash_hi_6, video_hash_lo_6]);
    let nullifier_7 = std::hash::pedersen_hash([credential_secret, nullifier_secret, video_hash_hi_7, video_hash_lo_7]);

    (
        (canonical_root, nullifier_0),
        (canonical_root, nullifier_1),
        (canonical_root, nullifier_2),
        (canonical_root, nullifier_3),
        (canonical_root, nullifier_4),
        (canonical_root, nullifier_5),
        (canonical_root, nullifier_6),
        (canonical_root, nullifier_7),
    )
}

// =============================================================================
// Test corpus
// =============================================================================

/// Verify the helper produces consistent outputs for matching secrets.
#[test]
fn test_helper_consistent_output() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let cr = std::hash::pedersen_hash([cs]);

    let vhi_0: Field = 22685491128062564230891640495451214097;
    let vlo_0: Field = 45370982256125128461783280990902428194;
    let nf_0 = std::hash::pedersen_hash([cs, ns, vhi_0, vlo_0]);

    let z: Field = 0;
    let result = main(cs, ns,
        vhi_0, vlo_0,
        z, z,
        z + 10, z + 10,
        z + 20, z + 20,
        z + 30, z + 30,
        z + 40, z + 40,
        z + 50, z + 50,
        z + 60, z + 60,
    );

    // Assert all credential roots match.
    assert(result[0].0 == cr, "root 0 mismatch");
    assert(result[1].0 == cr, "root 1 mismatch");
    assert(result[2].0 == cr, "root 2 mismatch");
    assert(result[3].0 == cr, "root 3 mismatch");
    assert(result[4].0 == cr, "root 4 mismatch");
    assert(result[5].0 == cr, "root 5 mismatch");
    assert(result[6].0 == cr, "root 6 mismatch");
    assert(result[7].0 == cr, "root 7 mismatch");

    // Assert nullifiers match per-element.
    assert(result[0].1 == nf_0, "nullifier 0 mismatch");
    assert(result[1].1 == std::hash::pedersen_hash([cs, ns, z, z]), "nullifier 1 mismatch");
    assert(result[2].1 == std::hash::pedersen_hash([cs, ns, z + 10, z + 10]), "nullifier 2 mismatch");
    assert(result[3].1 == std::hash::pedersen_hash([cs, ns, z + 20, z + 20]), "nullifier 3 mismatch");
    assert(result[4].1 == std::hash::pedersen_hash([cs, ns, z + 30, z + 30]), "nullifier 4 mismatch");
    assert(result[5].1 == std::hash::pedersen_hash([cs, ns, z + 40, z + 40]), "nullifier 5 mismatch");
    assert(result[6].1 == std::hash::pedersen_hash([cs, ns, z + 50, z + 50]), "nullifier 6 mismatch");
    assert(result[7].1 == std::hash::pedersen_hash([cs, ns, z + 60, z + 60]), "nullifier 7 mismatch");
}
