use std::hash::pedersen_hash;

global MAX_ATTRIBUTES: u32 = 16;
global MAX_PREDICATES: u32 = 8;
global MAX_SET_MEMBERS: u32 = 8;
global CURRENT_CIRCUIT_VERSION: u32 = 1;

unconstrained fn eq_predicate_type() -> Field {
    0
}

unconstrained fn set_membership_predicate_type() -> Field {
    1
}

unconstrained fn range_predicate_type() -> Field {
    2
}

fn assert_valid_predicate_type(predicate_type: Field) {
    assert(
        predicate_type == eq_predicate_type()
        || predicate_type == set_membership_predicate_type()
        || predicate_type == range_predicate_type(),
        "unsupported predicate type",
    );
}

fn attr_commitment(value: Field, blinding: Field) -> Field {
    pedersen_hash([value, blinding])
}

fn compute_credential_root(
    commitments: [Field; MAX_ATTRIBUTES],
    num_attributes: u32,
) -> Field {
    let mut current = commitments[0];
    let mut i: u32 = 1;
    for _ in 0..MAX_ATTRIBUTES - 1 {
        if i < num_attributes {
            current = pedersen_hash([current, commitments[i]]);
            i = i + 1;
        }
    }
    current
}

fn verify_predicate(
    predicate_type: Field,
    attr_value: Field,
    public_value: Field,
    set_values: [Field; MAX_SET_MEMBERS],
    set_len: u32,
    lower_bound: Field,
    upper_bound: Field,
) {
    if predicate_type == eq_predicate_type() {
        assert(attr_value == public_value, "equality predicate failed");
    } else if predicate_type == set_membership_predicate_type() {
        let mut found = false;
        for i in 0..MAX_SET_MEMBERS {
            if i < set_len {
                if set_values[i] == attr_value {
                    found = true;
                }
            }
        }
        assert(found, "set membership predicate failed");
    } else if predicate_type == range_predicate_type() {
        assert(attr_value >= lower_bound, "range predicate: below lower bound");
        assert(attr_value <= upper_bound, "range predicate: above upper bound");
    } else {
        assert(false, "unknown predicate type");
    }
}

fn compute_predicate_commitment(
    predicates: [Predicate; MAX_PREDICATES],
    num_predicates: u32,
) -> Field {
    let mut current: Field = 0;
    let mut i: u32 = 0;
    for _ in 0..MAX_PREDICATES {
        if i < num_predicates {
            let p = predicates[i];
            current = pedersen_hash([
                current,
                p.predicate_type,
                p.attr_index as Field,
                p.public_value,
            ]);
            i = i + 1;
        }
    }
    current
}

struct Predicate {
    predicate_type: Field,
    attr_index: u32,
    public_value: Field,
    set_values: [Field; MAX_SET_MEMBERS],
    set_len: u32,
    lower_bound: Field,
    upper_bound: Field,
}

fn main(
    schema_hash: pub Field,
    issuer_namespace: pub Field,
    schema_version: pub Field,
    credential_root: pub Field,
    nullifier: pub Field,
    video_hash_hi: pub Field,
    video_hash_lo: pub Field,
    verifier_digest: pub Field,
    circuit_version: pub Field,
    evidence_digest: pub Field,
    predicate_commitment: pub Field,
    num_attributes: u32,
    attr_values: [Field; MAX_ATTRIBUTES],
    attr_blindings: [Field; MAX_ATTRIBUTES],
    num_predicates: u32,
    predicates: [Predicate; MAX_PREDICATES],
) {
    for i in 0..MAX_PREDICATES {
        if i < num_predicates {
            assert_valid_predicate_type(predicates[i].predicate_type);
        }
    }

    assert(
        circuit_version == CURRENT_CIRCUIT_VERSION as Field,
        "circuit version mismatch",
    );

    assert(num_attributes > 0, "at least one attribute required");
    assert(num_attributes <= MAX_ATTRIBUTES, "too many attributes");
    assert(num_predicates <= MAX_PREDICATES, "too many predicates");
    for i in 0..MAX_PREDICATES {
        if i < num_predicates {
            assert(
                predicates[i].attr_index < num_attributes,
                "predicate attribute index out of range",
            );
            if predicates[i].predicate_type == set_membership_predicate_type() {
                assert(
                    predicates[i].set_len > 0,
                    "set membership predicate requires non-empty set",
                );
                assert(
                    predicates[i].set_len <= MAX_SET_MEMBERS,
                    "set membership predicate: too many set values",
                );
            }
        }
    }

    let mut commitments: [Field; MAX_ATTRIBUTES] = [0; MAX_ATTRIBUTES];
    for i in 0..MAX_ATTRIBUTES {
        if i < num_attributes {
            commitments[i] = attr_commitment(attr_values[i], attr_blindings[i]);
        }
    }

    let derived_root = compute_credential_root(commitments, num_attributes);
    assert(derived_root == credential_root, "credential root mismatch");

    for i in 0..MAX_PREDICATES {
        if i < num_predicates {
            let pred = predicates[i];
            verify_predicate(
                pred.predicate_type,
                attr_values[pred.attr_index],
                pred.public_value,
                pred.set_values,
                pred.set_len,
                pred.lower_bound,
                pred.upper_bound,
            );
        }
    }

    let derived_pred_commitment = compute_predicate_commitment(predicates, num_predicates);
    assert(
        derived_pred_commitment == predicate_commitment,
        "predicate commitment mismatch",
    );

    let derived_nullifier = pedersen_hash([
        credential_root,
        video_hash_hi,
        video_hash_lo,
        evidence_digest,
    ]);
    assert(derived_nullifier == nullifier, "nullifier mismatch");

    let derived_verifier_digest = pedersen_hash([
        verifier_digest,
        schema_hash,
        circuit_version,
    ]);
    assert(verifier_digest != 0, "verifier digest must be non-zero");
}

fn make_predicate(
    predicate_type: Field,
    attr_index: u32,
    public_value: Field,
    set_values: [Field; 8],
    set_len: u32,
    lower_bound: Field,
    upper_bound: Field,
) -> Predicate {
    Predicate {
        predicate_type,
        attr_index,
        public_value,
        set_values,
        set_len,
        lower_bound,
        upper_bound,
    }
}

fn default_attr_values() -> [Field; 16] {
    [18, 12345678, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn default_blindings() -> [Field; 16] {
    [111111, 222222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn default_padding_predicates() -> [Predicate; 8] {
    [make_predicate(0, 0, 0, [0; 8], 0, 0, 0); 8]
}

fn default_preds() -> [Predicate; 8] {
    let mut p = default_padding_predicates();
    p[0] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    p
}

fn run_test(
    schema_hash: Field,
    num_attributes: u32,
    attr_values: [Field; 16],
    attr_blindings: [Field; 16],
    num_predicates: u32,
    predicates: [Predicate; 8],
    expected_fail: bool,
) {
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        if i < num_attributes {
            commitments[i] = attr_commitment(attr_values[i], attr_blindings[i]);
        }
    }
    let credential_root = compute_credential_root(commitments, num_attributes);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let predicate_commitment = compute_predicate_commitment(predicates, num_predicates);
    let verifier_digest = 42;

    if expected_fail {
    }

    main(
        schema_hash,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        verifier_digest,
        1,
        9999,
        predicate_commitment,
        num_attributes,
        attr_values,
        attr_blindings,
        num_predicates,
        predicates,
    );
}

#[test]
fn test_valid_equality_predicate() {
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        default_preds(),
        false,
    );
}

#[test]
fn test_valid_range_predicate() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 18, 99);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_valid_set_membership_predicate() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(1, 1, 0, [12345678, 87654321, 11111111, 0, 0, 0, 0, 0], 3, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_valid_multiple_predicates() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[1] = make_predicate(1, 1, 0, [12345678, 87654321, 11111111, 0, 0, 0, 0, 0], 3, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        2,
        preds,
        false,
    );
}

#[test]
fn test_range_lower_bound_edge() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 18, 99);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_range_upper_bound_edge() {
    let mut attr_vals = default_attr_values();
    attr_vals[0] = 99;
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 18, 99);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attr_vals,
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_set_membership_single_element() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(1, 1, 0, [12345678, 0, 0, 0, 0, 0, 0, 0], 1, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test(should_fail_with = "equality predicate failed")]
fn test_equality_wrong_value() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(0, 0, 21, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "range predicate: below lower bound")]
fn test_range_below_lower() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 21, 99);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "range predicate: above upper bound")]
fn test_range_above_upper() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 18, 17);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "set membership predicate failed")]
fn test_set_membership_not_in_set() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(1, 1, 0, [87654321, 11111111, 0, 0, 0, 0, 0, 0], 2, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "set membership predicate requires non-empty set")]
fn test_set_membership_empty_set() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(1, 1, 0, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "credential root mismatch")]
fn test_wrong_credential_root() {
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        default_preds(),
        true,
    );
}

#[test(should_fail_with = "credential root mismatch")]
fn test_wrong_attribute_value() {
    let mut attr_vals = default_attr_values();
    attr_vals[0] = 19;
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attr_vals,
        default_blindings(),
        1,
        default_preds(),
        true,
    );
}

#[test(should_fail_with = "credential root mismatch")]
fn test_wrong_blinding() {
    let mut blindings = default_blindings();
    blindings[0] = 999999;
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        blindings,
        1,
        default_preds(),
        true,
    );
}

#[test(should_fail_with = "circuit version mismatch")]
fn test_circuit_version_downgrade() {
    let attr_vals = default_attr_values();
    let blindings = default_blindings();
    let num_attributes: u32 = 2;
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        if i < num_attributes {
            commitments[i] = attr_commitment(attr_vals[i], blindings[i]);
        }
    }
    let credential_root = compute_credential_root(commitments, num_attributes);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let preds = default_preds();
    let predicate_commitment = compute_predicate_commitment(preds, 1);

    main(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        42,
        0,
        9999,
        predicate_commitment,
        num_attributes,
        attr_vals,
        blindings,
        1,
        preds,
    );
}

#[test(should_fail_with = "at least one attribute required")]
fn test_zero_attributes() {
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0,
        default_attr_values(),
        default_blindings(),
        1,
        default_preds(),
        true,
    );
}

#[test(should_fail_with = "too many predicates")]
fn test_too_many_predicates() {
    let mut preds = default_preds();
    preds[0] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[1] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[2] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[3] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[4] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[5] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[6] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[7] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        9,
        preds,
        true,
    );
}

#[test(should_fail_with = "unsupported predicate type")]
fn test_unsupported_predicate_type() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(42, 0, 0, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "predicate attribute index out of range")]
fn test_predicate_out_of_range_attr_index() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(0, 99, 18, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "predicate commitment mismatch")]
fn test_predicate_commitment_mismatch() {
    let attr_vals = default_attr_values();
    let blindings = default_blindings();
    let num_attributes: u32 = 2;
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        if i < num_attributes {
            commitments[i] = attr_commitment(attr_vals[i], blindings[i]);
        }
    }
    let credential_root = compute_credential_root(commitments, num_attributes);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let preds = default_preds();

    main(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        42,
        1,
        9999,
        0,
        num_attributes,
        attr_vals,
        blindings,
        1,
        preds,
    );
}

#[test(should_fail_with = "verifier digest must be non-zero")]
fn test_zero_verifier_digest() {
    let attr_vals = default_attr_values();
    let blindings = default_blindings();
    let num_attributes: u32 = 2;
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        if i < num_attributes {
            commitments[i] = attr_commitment(attr_vals[i], blindings[i]);
        }
    }
    let credential_root = compute_credential_root(commitments, num_attributes);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let preds = default_preds();
    let predicate_commitment = compute_predicate_commitment(preds, 1);

    main(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        0,
        1,
        9999,
        predicate_commitment,
        num_attributes,
        attr_vals,
        blindings,
        1,
        preds,
    );
}
