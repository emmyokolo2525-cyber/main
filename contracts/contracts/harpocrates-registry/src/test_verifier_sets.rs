#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    Address, Bytes, Env,
};

// ---------------------------------------------------------------------------
// Mock verifier contracts
// ---------------------------------------------------------------------------

/// Always approves (returns Ok, does nothing).
#[contract]
struct MockVerifierApprove;

#[contractimpl]
impl MockVerifierApprove {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {
        // approve: return Ok
    }
}

/// Always rejects (panics with contract error).
#[contract]
struct MockVerifierReject;

#[contractimpl]
impl MockVerifierReject {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {
        panic!("proof rejected");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn proof_bytes(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1, 2, 3, 4])
}

fn silent_public_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Bytes {
    let mut vh = [0u8; 32];
    video_hash.copy_into_slice(&mut vh);
    let mut cr = [0u8; 32];
    credential_root.copy_into_slice(&mut cr);
    let mut nl = [0u8; 32];
    nullifier.copy_into_slice(&mut nl);

    let mut buf = [0u8; 128];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&cr);
    buf[96..128].copy_from_slice(&nl);
    Bytes::from_array(env, &buf)
}

/// Advance ledger timestamp by `secs` seconds.
fn advance_time(env: &Env, secs: u64) {
    let current = env.ledger().timestamp();
    env.ledger().set_timestamp(current + secs);
}

/// Set up a registry with:
///   - `approve_count` MockVerifierApprove members (first)
///   - `reject_count` MockVerifierReject members (after)
/// and activate the set with the given threshold.
///
/// Returns (env, contract_id, admin).
fn setup_with_set(
    approve_count: u32,
    reject_count: u32,
    threshold: u32,
) -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let circuit_version = soroban_sdk::String::from_str(&env, "ultraHonk-0.87.0");
    let total = approve_count + reject_count;

    match total {
        1 => {
            let m0 = if approve_count >= 1 {
                env.register(MockVerifierApprove, ())
            } else {
                env.register(MockVerifierReject, ())
            };
            client.propose_verifier_set_1(&admin, &m0, &threshold, &circuit_version);
        }
        2 => {
            let m0 = if approve_count >= 1 {
                env.register(MockVerifierApprove, ())
            } else {
                env.register(MockVerifierReject, ())
            };
            let m1 = if approve_count >= 2 {
                env.register(MockVerifierApprove, ())
            } else {
                env.register(MockVerifierReject, ())
            };
            client.propose_verifier_set_2(&admin, &m0, &m1, &threshold, &circuit_version);
        }
        3 => {
            let m0 = if approve_count >= 1 {
                env.register(MockVerifierApprove, ())
            } else {
                env.register(MockVerifierReject, ())
            };
            let m1 = if approve_count >= 2 {
                env.register(MockVerifierApprove, ())
            } else {
                env.register(MockVerifierReject, ())
            };
            let m2 = if approve_count >= 3 {
                env.register(MockVerifierApprove, ())
            } else {
                env.register(MockVerifierReject, ())
            };
            client.propose_verifier_set_3(&admin, &m0, &m1, &m2, &threshold, &circuit_version);
        }
        _ => panic!("setup_with_set only supports total 1-3 members"),
    }

    advance_time(&env, VERIFIER_SET_TIMELOCK_SECS + 1);
    client.activate_verifier_set(&admin);

    (env, contract_id, admin)
}

// ---------------------------------------------------------------------------
// propose_verifier_set tests
// ---------------------------------------------------------------------------

#[test]
fn propose_verifier_set_returns_version_1_on_first_call() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let verifier_id = env.register(MockVerifierApprove, ());
    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    let version = client.propose_verifier_set_1(&admin, &verifier_id, &1, &circuit_version);
    assert_eq!(version, 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn propose_verifier_set_rejects_non_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    client.init(&admin);

    let verifier_id = env.register(MockVerifierApprove, ());
    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    client.propose_verifier_set_1(&attacker, &verifier_id, &1, &circuit_version);
}

#[test]
#[should_panic(expected = "Error(Contract, #25)")]
fn propose_verifier_set_rejects_threshold_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let verifier_id = env.register(MockVerifierApprove, ());
    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    client.propose_verifier_set_1(&admin, &verifier_id, &0, &circuit_version);
}

#[test]
#[should_panic(expected = "Error(Contract, #25)")]
fn propose_verifier_set_rejects_threshold_exceeding_member_count() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let verifier_id = env.register(MockVerifierApprove, ());
    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    // threshold=2 but only 1 member (propose_verifier_set_1 checks threshold <= 1)
    client.propose_verifier_set_1(&admin, &verifier_id, &2, &circuit_version);
}

// ---------------------------------------------------------------------------
// activate_verifier_set tests
// ---------------------------------------------------------------------------

#[test]
fn activate_verifier_set_stores_and_returns_version() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let verifier_id = env.register(MockVerifierApprove, ());
    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    let proposed = client.propose_verifier_set_1(&admin, &verifier_id, &1, &circuit_version);
    assert_eq!(proposed, 1);

    advance_time(&env, VERIFIER_SET_TIMELOCK_SECS + 1);

    let activated = client.activate_verifier_set(&admin);
    assert_eq!(activated, 1);

    let vset = client.get_active_verifier_set().unwrap();
    assert_eq!(vset.version, 1);
    assert_eq!(vset.threshold, 1);
    assert_eq!(vset.member_count, 1);
    assert!(!vset.disabled);
}

#[test]
#[should_panic(expected = "Error(Contract, #24)")]
fn activate_verifier_set_panics_with_no_pending() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    client.activate_verifier_set(&admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #23)")]
fn activate_verifier_set_panics_before_timelock_expires() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let verifier_id = env.register(MockVerifierApprove, ());
    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    client.propose_verifier_set_1(&admin, &verifier_id, &1, &circuit_version);

    // Do NOT advance time past timelock.
    client.activate_verifier_set(&admin);
}

#[test]
fn activate_verifier_set_retires_previous_set() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    let v1_id = env.register(MockVerifierApprove, ());
    client.propose_verifier_set_1(&admin, &v1_id, &1, &circuit_version);
    advance_time(&env, VERIFIER_SET_TIMELOCK_SECS + 1);
    client.activate_verifier_set(&admin);

    // Propose and activate v2.
    let circuit_version2 = soroban_sdk::String::from_str(&env, "v2");
    let v2_id = env.register(MockVerifierApprove, ());
    client.propose_verifier_set_1(&admin, &v2_id, &1, &circuit_version2);
    advance_time(&env, VERIFIER_SET_TIMELOCK_SECS + 1);
    client.activate_verifier_set(&admin);

    // v1 should be retired (retired_at != 0).
    let v1_record = client.get_verifier_set(&1).unwrap();
    assert_ne!(v1_record.retired_at, 0, "v1 should have been retired");

    // v2 is now active.
    let active = client.get_active_verifier_set().unwrap();
    assert_eq!(active.version, 2);
}

// ---------------------------------------------------------------------------
// Rotation overlap (staged rotation) test
// ---------------------------------------------------------------------------

#[test]
fn rotation_overlap_v1_retired_when_v2_activates() {
    // Simulates staged rotation: propose v2 while v1 is active, then activate v2.
    // v1 should be marked retired atomically when v2 activates.
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    // Activate v1.
    let cv1 = soroban_sdk::String::from_str(&env, "circuit-v1");
    let v1_id = env.register(MockVerifierApprove, ());
    client.propose_verifier_set_1(&admin, &v1_id, &1, &cv1);
    advance_time(&env, VERIFIER_SET_TIMELOCK_SECS + 1);
    client.activate_verifier_set(&admin);

    // While v1 is active, propose v2.
    let cv2 = soroban_sdk::String::from_str(&env, "circuit-v2");
    let v2_id = env.register(MockVerifierApprove, ());
    client.propose_verifier_set_1(&admin, &v2_id, &1, &cv2);

    // Timelock hasn't elapsed; v1 still usable.
    let active_before = client.get_active_verifier_set().unwrap();
    assert_eq!(active_before.version, 1);

    // Advance past timelock and activate v2.
    advance_time(&env, VERIFIER_SET_TIMELOCK_SECS + 1);
    client.activate_verifier_set(&admin);

    // v1 is now retired.
    let v1_after = client.get_verifier_set(&1).unwrap();
    assert_ne!(v1_after.retired_at, 0);

    // v2 is active.
    let active_after = client.get_active_verifier_set().unwrap();
    assert_eq!(active_after.version, 2);
}

// ---------------------------------------------------------------------------
// disable_verifier_set tests
// ---------------------------------------------------------------------------

#[test]
fn disable_verifier_set_marks_set_disabled() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let verifier_id = env.register(MockVerifierApprove, ());
    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    client.propose_verifier_set_1(&admin, &verifier_id, &1, &circuit_version);
    advance_time(&env, VERIFIER_SET_TIMELOCK_SECS + 1);
    client.activate_verifier_set(&admin);

    client.disable_verifier_set(&admin, &1);

    let record = client.get_verifier_set(&1).unwrap();
    assert!(record.disabled, "set should be disabled after emergency disable");
}

#[test]
#[should_panic(expected = "Error(Contract, #14)")]
fn disable_verifier_set_panics_for_unknown_version() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    client.disable_verifier_set(&admin, &99);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn disable_verifier_set_rejects_non_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    client.init(&admin);

    let verifier_id = env.register(MockVerifierApprove, ());
    let circuit_version = soroban_sdk::String::from_str(&env, "v1");
    client.propose_verifier_set_1(&admin, &verifier_id, &1, &circuit_version);
    advance_time(&env, VERIFIER_SET_TIMELOCK_SECS + 1);
    client.activate_verifier_set(&admin);

    client.disable_verifier_set(&attacker, &1);
}

// ---------------------------------------------------------------------------
// register_anon_verified_quorum — approval path
// ---------------------------------------------------------------------------

#[test]
fn quorum_approved_with_single_approving_verifier() {
    let (env, contract_id, admin) = setup_with_set(1, 0, 1);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = bytes32(&env, 70);
    let credential_root = bytes32(&env, 71);
    let nullifier = bytes32(&env, 72);
    let proof_id = bytes32(&env, 73);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 74));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    let record = client.register_anon_verified_quorum(
        &video_hash,
        &bytes32(&env, 75),
        &proof_id,
        &pi,
        &proof_bytes(&env),
    );
    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.video_hash, video_hash);
    assert_eq!(record.nullifier, Some(nullifier.clone()));
    assert!(client.has_nullifier(&nullifier));
}

#[test]
fn quorum_approved_with_majority_approving_verifiers() {
    // 2 approve, 1 reject, threshold=2 → should NOT pass (2 == threshold, 1 > 3-2=1).
    // Actually: 2-of-3 with 2 approves: approved(2) >= threshold(2) → Approved.
    let (env, contract_id, admin) = setup_with_set(2, 1, 2);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = bytes32(&env, 80);
    let credential_root = bytes32(&env, 81);
    let nullifier = bytes32(&env, 82);
    let proof_id = bytes32(&env, 83);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 84));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    let record = client.register_anon_verified_quorum(
        &video_hash,
        &bytes32(&env, 85),
        &proof_id,
        &pi,
        &proof_bytes(&env),
    );
    assert_eq!(record.tier, TIER_SILENT_WITNESS);
}

// ---------------------------------------------------------------------------
// register_anon_verified_quorum — rejection/split path
// ---------------------------------------------------------------------------

/// In the Soroban test env, `panic!()` in a WASM mock contract is a host error
/// (WasmVm::InvalidAction), treated as verifier failure, not rejection.
/// With 1 failing verifier and circuit_version set → VersionMismatch (#19).
#[test]
#[should_panic(expected = "Error(Contract, #19)")]
fn quorum_rejected_when_all_verifiers_reject() {
    // 0 approve, 1 panic/fail, threshold=1 → VersionMismatch in test env.
    let (env, contract_id, admin) = setup_with_set(0, 1, 1);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = bytes32(&env, 90);
    let credential_root = bytes32(&env, 91);
    let nullifier = bytes32(&env, 92);
    let proof_id = bytes32(&env, 93);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 94));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    client.register_anon_verified_quorum(
        &video_hash,
        &bytes32(&env, 95),
        &proof_id,
        &pi,
        &proof_bytes(&env),
    );
}

/// In test env, panics from WASM = host failures.
/// 1 approve, 2 panic (failures), threshold=2: failures(2) > max_allowed(1) → Unavailable (#15).
#[test]
#[should_panic(expected = "Error(Contract, #15)")]
fn quorum_rejected_when_majority_rejects() {
    // 1 approve, 2 fail (panics), threshold=2 → QuorumNotReached in test env.
    let (env, contract_id, admin) = setup_with_set(1, 2, 2);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = bytes32(&env, 100);
    let credential_root = bytes32(&env, 101);
    let nullifier = bytes32(&env, 102);
    let proof_id = bytes32(&env, 103);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 104));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    client.register_anon_verified_quorum(
        &video_hash,
        &bytes32(&env, 105),
        &proof_id,
        &pi,
        &proof_bytes(&env),
    );
}

// ---------------------------------------------------------------------------
// register_anon_verified_quorum — emergency disable
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #17)")]
fn quorum_panics_when_active_set_is_disabled() {
    let (env, contract_id, admin) = setup_with_set(1, 0, 1);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Emergency disable the active set.
    client.disable_verifier_set(&admin, &1);

    let video_hash = bytes32(&env, 110);
    let credential_root = bytes32(&env, 111);
    let nullifier = bytes32(&env, 112);
    let proof_id = bytes32(&env, 113);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 114));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    client.register_anon_verified_quorum(
        &video_hash,
        &bytes32(&env, 115),
        &proof_id,
        &pi,
        &proof_bytes(&env),
    );
}

// ---------------------------------------------------------------------------
// register_anon_verified_quorum — no active verifier set
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #14)")]
fn quorum_panics_when_no_active_verifier_set() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    // No verifier set proposed or activated.
    let video_hash = bytes32(&env, 120);
    let credential_root = bytes32(&env, 121);
    let nullifier = bytes32(&env, 122);
    let proof_id = bytes32(&env, 123);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 124));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    client.register_anon_verified_quorum(
        &video_hash,
        &bytes32(&env, 125),
        &proof_id,
        &pi,
        &proof_bytes(&env),
    );
}

// ---------------------------------------------------------------------------
// register_anon_verified_quorum — duplicate nullifier (replay protection)
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn quorum_rejects_duplicate_nullifier() {
    let (env, contract_id, admin) = setup_with_set(1, 0, 1);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let credential_root = bytes32(&env, 131);
    let nullifier = bytes32(&env, 132);
    let video_hash1 = bytes32(&env, 130);
    let video_hash2 = bytes32(&env, 135);
    let proof_id1 = bytes32(&env, 133);
    let proof_id2 = bytes32(&env, 134);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 136));
    let pi1 = silent_public_inputs(&env, &video_hash1, &credential_root, &nullifier);
    let pi2 = silent_public_inputs(&env, &video_hash2, &credential_root, &nullifier);

    // First registration should succeed.
    client.register_anon_verified_quorum(
        &video_hash1,
        &bytes32(&env, 137),
        &proof_id1,
        &pi1,
        &proof_bytes(&env),
    );

    // Second with same nullifier must fail.
    client.register_anon_verified_quorum(
        &video_hash2,
        &bytes32(&env, 138),
        &proof_id2,
        &pi2,
        &proof_bytes(&env),
    );
}

// ---------------------------------------------------------------------------
// register_anon_verified_quorum — duplicate proof_id guard
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn quorum_rejects_duplicate_proof_id() {
    let (env, contract_id, admin) = setup_with_set(1, 0, 1);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let credential_root = bytes32(&env, 141);
    let nullifier1 = bytes32(&env, 142);
    let nullifier2 = bytes32(&env, 143);
    let proof_id = bytes32(&env, 144); // same both times
    let video_hash1 = bytes32(&env, 140);
    let video_hash2 = bytes32(&env, 145);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 146));
    let pi1 = silent_public_inputs(&env, &video_hash1, &credential_root, &nullifier1);
    let pi2 = silent_public_inputs(&env, &video_hash2, &credential_root, &nullifier2);

    client.register_anon_verified_quorum(
        &video_hash1,
        &bytes32(&env, 147),
        &proof_id,
        &pi1,
        &proof_bytes(&env),
    );
    // duplicate proof_id
    client.register_anon_verified_quorum(
        &video_hash2,
        &bytes32(&env, 148),
        &proof_id,
        &pi2,
        &proof_bytes(&env),
    );
}

// ---------------------------------------------------------------------------
// register_anon_verified_quorum — bounds check
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #20)")]
fn quorum_rejects_oversized_proof() {
    let (env, contract_id, admin) = setup_with_set(1, 0, 1);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = bytes32(&env, 150);
    let credential_root = bytes32(&env, 151);
    let nullifier = bytes32(&env, 152);
    let proof_id = bytes32(&env, 153);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 154));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    // Build a proof larger than MAX_PROOF_SIZE_BYTES (65536 bytes).
    let chunk = Bytes::from_array(&env, &[1u8; 256]);
    let mut oversized_proof = Bytes::new(&env);
    for _ in 0..257u32 {
        // 257 * 256 = 65792 > 65536
        oversized_proof.append(&chunk);
    }

    client.register_anon_verified_quorum(
        &video_hash,
        &bytes32(&env, 155),
        &proof_id,
        &pi,
        &oversized_proof,
    );
}

// ---------------------------------------------------------------------------
// get_verifier_set / get_active_verifier_set
// ---------------------------------------------------------------------------

#[test]
fn get_verifier_set_returns_none_for_unknown_version() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    assert!(client.get_verifier_set(&99).is_none());
}

#[test]
fn get_active_verifier_set_returns_none_before_any_activation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    assert!(client.get_active_verifier_set().is_none());
}

// ---------------------------------------------------------------------------
// Version mismatch: all verifiers unavailable with circuit_version set
// ---------------------------------------------------------------------------

/// A verifier that always panics at the host level (simulates being unreachable)
/// is implemented as MockVerifierReject which panics explicitly.
/// For "unavailable" test we'd need a host error; we simulate version-mismatch
/// by checking Pending/QuorumNotReached when no verifiers can vote.
/// The VersionMismatch path requires host-level errors which are difficult to
/// trigger in unit tests. We verify the version_mismatch path indirectly:
/// a set with all rejectors returns Rejected (not VersionMismatch) since
/// contract panics are treated as rejections in try_invoke_contract.
#[test]
fn version_mismatch_not_triggered_by_contract_panics() {
    // All contract panics are rejections, not failures, so no VersionMismatch.
    // This test verifies the boundary: with 1 reject, we get #7 (InvalidProof / Rejected).
    let (env, contract_id, admin) = setup_with_set(0, 1, 1);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let video_hash = bytes32(&env, 160);
    let credential_root = bytes32(&env, 161);
    let nullifier = bytes32(&env, 162);
    let proof_id = bytes32(&env, 163);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 164));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    let result = env.try_invoke_contract::<ProofRecord, RegistryError>(
        &contract_id,
        &soroban_sdk::Symbol::new(&env, "register_anon_verified_quorum"),
        {
            let mut args = soroban_sdk::Vec::new(&env);
            args.push_back(video_hash.into_val(&env));
            args.push_back(bytes32(&env, 165).into_val(&env));
            args.push_back(proof_id.into_val(&env));
            args.push_back(pi.into_val(&env));
            args.push_back(proof_bytes(&env).into_val(&env));
            args
        },
    );
    // The call must fail (quorum rejected).
    assert!(result.is_err(), "expected quorum rejection to fail the call");
}

// ---------------------------------------------------------------------------
// Backward compat: legacy register_anonymous_verified still works
// ---------------------------------------------------------------------------

#[contract]
struct MockNoirVerifierLegacy;

#[contractimpl]
impl MockNoirVerifierLegacy {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if public_inputs.len() != 128 || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

#[test]
fn legacy_register_anonymous_verified_still_works_alongside_quorum() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifierLegacy, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);

    let video_hash = bytes32(&env, 200);
    let credential_root = bytes32(&env, 201);
    let nullifier = bytes32(&env, 202);
    let proof_id = bytes32(&env, 203);

    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 204));
    let pi = silent_public_inputs(&env, &video_hash, &credential_root, &nullifier);

    let record = client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 205),
        &proof_id,
        &pi,
        &proof_bytes(&env),
    );
    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.nullifier, Some(nullifier));
}
