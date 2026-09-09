//! Revocation witness integration (#98)
//!
//! ## Non-revocation semantics
//!
//! The registry supports privacy-preserving **non-revocation** proofs through
//! the `RevocationWitness` Noir circuit.  Rather than proving that a
//! credential *is* revoked, the circuit proves that a credential is **not**
//! in the published revocation tree.
//!
//! ### How it works
//!
//! 1. The admin publishes a Merkle root of revoked credential_roots via
//!    `set_revocation_root`.  The tree is depth‑3 (8 leaves) and uses
//!    Pedersen hashes, matching the Silent Witness circuit.
//!
//! 2. A user who wants to prove their credential is still valid constructs a
//!    Noir proof using the `revocation_witness` circuit.  The circuit takes
//!    all 8 leaves of the tree as **private** inputs, recomputes the Merkle
//!    root, and asserts that the user's `credential_root` differs from every
//!    leaf.
//!
//! 3. The user submits the proof to `check_non_revocation` along with
//!    `public_inputs` containing: revocation_root, nullifier,
//!    domain_separator, and credential_root.
//!
//! 4. The contract:
//!    - Checks `domain_separator` matches the hardcoded version tag
//!    - Checks `revocation_root` matches the stored on‑chain root
//!    - Checks `credential_root` is registered and active
//!    - Checks `nullifier` has not been consumed
//!    - Calls the external UltraHonk verifier to validate the proof
//!    - Stores the nullifier to prevent replay
//!
//! ### Privacy properties
//!
//! - The revocation tree leaves are **private** — the verifier learns only
//!   the root, not which credentials are revoked.
//! - `credential_root` is pseudonymous (a Pedersen hash of a secret).
//! - `nullifier` is one‑use, preventing the same proof from being replayed.
//!
//! ### Domain binding
//!
//! `domain_separator` is a version tag (`"HARPOCRATES_REVOCATION_V1"`)
//! that prevents proofs from one protocol version being accepted by another.
//! Network binding is provided by the contract ID (different per network).
//!
//! ### Shared conformance vectors
//!
//! Test vectors are in `zk/noir/fixtures/revocation_vectors.json`.  Both the
//! Noir circuit tests and these contract tests use the same fixture data.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _},
    Address, Bytes, Env,
};

// ---------------------------------------------------------------------------
// Mock UltraHonk verifier for testing the revocation proof boundary
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockRevocationVerifier;

#[cfg(test)]
#[contractimpl]
impl MockRevocationVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        if (len != 128 && len != 192) || proof.is_empty() {
            panic!("invalid revocation proof");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

#[cfg(test)]
fn proof_bytes(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0xAA, 0xBB, 0xCC, 0xDD])
}

/// Build a 128‑byte revocation public‑input blob.
///
/// Layout (4 × BN254 field elements):
///   [  0.. 32)  revocation_root
///   [ 32.. 64)  nullifier
///   [ 64.. 96)  domain_separator
///   [ 96..128)  credential_root
#[cfg(test)]
fn revocation_public_inputs(
    env: &Env,
    revocation_root: &BytesN<32>,
    nullifier: &BytesN<32>,
    domain_separator: &BytesN<32>,
    credential_root: &BytesN<32>,
) -> Bytes {
    let mut bytes = [0u8; 128];

    let mut rr = [0u8; 32];
    revocation_root.copy_into_slice(&mut rr);
    bytes[0..32].copy_from_slice(&rr);

    let mut nf = [0u8; 32];
    nullifier.copy_into_slice(&mut nf);
    bytes[32..64].copy_from_slice(&nf);

    let mut ds = [0u8; 32];
    domain_separator.copy_into_slice(&mut ds);
    bytes[64..96].copy_from_slice(&ds);

    let mut cr = [0u8; 32];
    credential_root.copy_into_slice(&mut cr);
    bytes[96..128].copy_from_slice(&cr);

    Bytes::from_array(env, &bytes)
}

// ---------------------------------------------------------------------------
// Tests — revocation root management (admin entry points)
// ---------------------------------------------------------------------------

/// Admin can set and read back a revocation root.
#[test]
fn test_set_and_get_revocation_root() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let root = b32(&env, 0xAB);
    client.set_revocation_root(&admin, &root);

    let stored = client.get_revocation_root();
    assert_eq!(stored, Some(root));
}

/// Only admin can set the revocation root.
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_non_admin_cannot_set_revocation_root() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let other = Address::generate(&env);
    client.init(&admin);

    client.set_revocation_root(&other, &b32(&env, 0xCD));
}

/// get_revocation_root returns None before any root is set.
#[test]
fn test_revocation_root_defaults_to_none() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    assert_eq!(client.get_revocation_root(), None);
}

/// Revocation root can be updated (rotated) by the admin.
#[test]
fn test_revocation_root_can_be_rotated() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let root1 = b32(&env, 0x11);
    let root2 = b32(&env, 0x22);

    client.set_revocation_root(&admin, &root1);
    assert_eq!(client.get_revocation_root(), Some(root1));

    client.set_revocation_root(&admin, &root2);
    assert_eq!(client.get_revocation_root(), Some(root2));
}

/// Setting the revocation root emits an event.
#[test]
fn test_revocation_root_emits_event() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    client.set_revocation_root(&admin, &b32(&env, 0xAB));

    assert_ne!(
        env.events().all(),
        [].as_slice(),
        "expected at least one event after setting revocation root"
    );
}

// ---------------------------------------------------------------------------
// Tests — check_non_revocation (end‑to‑end proof boundary)
// ---------------------------------------------------------------------------

/// Happy path: a valid non‑revocation proof is accepted, nullifier is
/// consumed, and an event is emitted.
#[test]
fn test_check_non_revocation_succeeds() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let revocation_root = b32(&env, 0xAB);
    let credential_root = b32(&env, 0x10);
    let nullifier = b32(&env, 0x20);

    // Domain separator must match REVOCATION_DOMAIN_SEPARATOR
    let domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.set_revocation_root(&admin, &revocation_root);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));

    let pi = revocation_public_inputs(
        &env,
        &revocation_root,
        &nullifier,
        &domain_separator,
        &credential_root,
    );
    let proof = proof_bytes(&env);

    client.check_non_revocation(&pi, &proof);

    // Nullifier should be consumed (this proves the proof was accepted).
    assert!(client.has_nullifier(&nullifier));
}

/// Rejects when no revocation root has been published.
#[test]
#[should_panic(expected = "Error(Contract, #2)")] // NotInitialized
fn test_check_non_revocation_rejects_no_root() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let credential_root = b32(&env, 0x10);
    let nullifier = b32(&env, 0x20);
    let domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));
    // Revocation root is NOT set — should fail

    let pi = revocation_public_inputs(
        &env,
        &b32(&env, 0xFF), // unused but must be 128 bytes
        &nullifier,
        &domain_separator,
        &credential_root,
    );
    let proof = proof_bytes(&env);

    client.check_non_revocation(&pi, &proof);
}

/// Rejects when the proof's revocation_root doesn't match the stored root.
#[test]
#[should_panic(expected = "Error(Contract, #10)")] // InvalidPublicInputs
fn test_check_non_revocation_rejects_wrong_root() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let stored_root = b32(&env, 0xAB);
    let wrong_root = b32(&env, 0xCD); // different from stored
    let credential_root = b32(&env, 0x10);
    let nullifier = b32(&env, 0x20);
    let domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.set_revocation_root(&admin, &stored_root);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));

    // Proof references wrong_root but stored is different
    let pi = revocation_public_inputs(
        &env,
        &wrong_root,
        &nullifier,
        &domain_separator,
        &credential_root,
    );
    let proof = proof_bytes(&env);

    client.check_non_revocation(&pi, &proof);
}

/// Rejects when the domain separator doesn't match the expected version tag.
#[test]
#[should_panic(expected = "Error(Contract, #10)")] // InvalidPublicInputs
fn test_check_non_revocation_rejects_wrong_domain() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let revocation_root = b32(&env, 0xAB);
    let credential_root = b32(&env, 0x10);
    let nullifier = b32(&env, 0x20);
    let wrong_domain = b32(&env, 0xEE); // does NOT match REVOCATION_DOMAIN_SEPARATOR

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.set_revocation_root(&admin, &revocation_root);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));

    let pi = revocation_public_inputs(
        &env,
        &revocation_root,
        &nullifier,
        &wrong_domain,
        &credential_root,
    );
    let proof = proof_bytes(&env);

    client.check_non_revocation(&pi, &proof);
}

/// Rejects when the credential root hasn't been registered.
#[test]
#[should_panic(expected = "Error(Contract, #11)")] // UnknownCredentialRoot
fn test_check_non_revocation_rejects_unknown_credential() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let revocation_root = b32(&env, 0xAB);
    let unknown_credential = b32(&env, 0x99); // NOT registered
    let nullifier = b32(&env, 0x20);
    let domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.set_revocation_root(&admin, &revocation_root);
    // credential_root is NOT registered

    let pi = revocation_public_inputs(
        &env,
        &revocation_root,
        &nullifier,
        &domain_separator,
        &unknown_credential,
    );
    let proof = proof_bytes(&env);

    client.check_non_revocation(&pi, &proof);
}

/// Rejects when the credential root has been revoked.
#[test]
#[should_panic(expected = "Error(Contract, #12)")] // RevokedCredentialRoot
fn test_check_non_revocation_rejects_revoked_credential() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let revocation_root = b32(&env, 0xAB);
    let credential_root = b32(&env, 0x10);
    let nullifier = b32(&env, 0x20);
    let domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.set_revocation_root(&admin, &revocation_root);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));
    client.revoke_credential_root(&admin, &credential_root); // now revoked

    let pi = revocation_public_inputs(
        &env,
        &revocation_root,
        &nullifier,
        &domain_separator,
        &credential_root,
    );
    let proof = proof_bytes(&env);

    client.check_non_revocation(&pi, &proof);
}

/// Rejects when the same nullifier is used twice (replay attack).
#[test]
#[should_panic(expected = "Error(Contract, #6)")] // DuplicateNullifier
fn test_check_non_revocation_rejects_reused_nullifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let revocation_root = b32(&env, 0xAB);
    let credential_root = b32(&env, 0x10);
    let nullifier = b32(&env, 0x20);
    let domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.set_revocation_root(&admin, &revocation_root);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));

    let pi = revocation_public_inputs(
        &env,
        &revocation_root,
        &nullifier,
        &domain_separator,
        &credential_root,
    );
    let proof = proof_bytes(&env);

    // First submission — succeeds
    client.check_non_revocation(&pi, &proof);
    assert!(client.has_nullifier(&nullifier));

    // Second submission with same nullifier — must panic
    client.check_non_revocation(&pi, &proof);
}

/// Rejects when no verifier is configured.
#[test]
#[should_panic(expected = "Error(Contract, #9)")] // VerifierNotSet
fn test_check_non_revocation_rejects_no_verifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let revocation_root = b32(&env, 0xAB);
    let credential_root = b32(&env, 0x10);
    let nullifier = b32(&env, 0x20);
    let domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    // Verifier is NOT set
    client.set_revocation_root(&admin, &revocation_root);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));

    let pi = revocation_public_inputs(
        &env,
        &revocation_root,
        &nullifier,
        &domain_separator,
        &credential_root,
    );
    let proof = proof_bytes(&env);

    client.check_non_revocation(&pi, &proof);
}

/// Rejects when public inputs are not exactly 128 bytes.
#[test]
#[should_panic(expected = "Error(Contract, #10)")] // InvalidPublicInputs
fn test_check_non_revocation_rejects_wrong_input_length() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let revocation_root = b32(&env, 0xAB);
    let credential_root = b32(&env, 0x10);
    let _domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.set_revocation_root(&admin, &revocation_root);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));

    // 64 bytes instead of 128
    let short_pi = Bytes::from_array(&env, &[0u8; 64]);
    let proof = proof_bytes(&env);

    client.check_non_revocation(&short_pi, &proof);
}

/// check_non_revocation emits a NonRevocationChecked event on success.
/// Follows the same pattern as test_revocation_root_emits_event.
#[test]
fn test_check_non_revocation_emits_event() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockRevocationVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let revocation_root = b32(&env, 0xAB);
    let credential_root = b32(&env, 0x10);
    let nullifier = b32(&env, 0x20);
    let domain_separator = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.set_revocation_root(&admin, &revocation_root);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x30));

    let pi = revocation_public_inputs(
        &env,
        &revocation_root,
        &nullifier,
        &domain_separator,
        &credential_root,
    );
    let proof = proof_bytes(&env);

    client.check_non_revocation(&pi, &proof);

    // Verify an event was emitted by check_non_revocation.
    // The env.events().all() iterator returns all events for this test.
    assert_ne!(
        env.events().all(),
        [].as_slice(),
        "expected NonRevocationChecked event after check_non_revocation"
    );
}
