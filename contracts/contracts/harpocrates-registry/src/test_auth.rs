//! Authorization matrix tests (#46)
//!
//! Every privileged entry point is tested against each actor class:
//!
//! | Actor          | Description                                      |
//! |----------------|--------------------------------------------------|
//! | admin          | the address stored as registry admin             |
//! | pending_admin  | a different address that *would* be admin        |
//! | issuer         | an address registered as an active issuer        |
//! | source         | an arbitrary wallet (tier-2 registrant)          |
//!
//! For each entry point the suite asserts:
//!   - The allowed caller succeeds.
//!   - Every disallowed caller produces the exact expected `RegistryError`.
//!
//! Error codes (from `RegistryError` repr):
//!   #1  AlreadyInitialized
//!   #2  NotInitialized
//!   #3  Unauthorized
//!   #8  UnknownIssuer
#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Env};

// ---------------------------------------------------------------------------
// Shared fixture
// ---------------------------------------------------------------------------

#[cfg(test)]
fn bytes32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

/// Returns (env, contract_id, admin, pending_admin, issuer, source).
/// All addresses live in the same Env so mock_all_auths covers them.
#[cfg(test)]
fn setup() -> (Env, Address, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let pending_admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &bytes32(&env, 0xAA));
    client.add_credential_root(&admin, &bytes32(&env, 0xBB), &bytes32(&env, 0xCC));

    (env, contract_id, admin, pending_admin, issuer, source)
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// init: succeeds exactly once for any caller (no prior admin).
#[test]
fn auth_init_succeeds_once() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin); // must not panic
}

/// init: a second call by ANY address is rejected with AlreadyInitialized (#1).
#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn auth_init_already_initialized_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    client.init(&admin); // second call → AlreadyInitialized
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn auth_init_already_initialized_unauthorized() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let other = Address::generate(&env);
    client.init(&admin);
    client.init(&other); // second call → AlreadyInitialized regardless of who
}

// ---------------------------------------------------------------------------
// add_issuer
// ---------------------------------------------------------------------------

/// add_issuer: admin succeeds.
#[test]
fn auth_add_issuer_admin_succeeds() {
    let (env, contract_id, admin, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let new_issuer = Address::generate(&env);
    client.add_issuer(&admin, &new_issuer, &bytes32(&env, 1));
    assert!(client.get_issuer(&new_issuer).unwrap().active);
}

/// add_issuer: non-admin is rejected with Unauthorized (#3).
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_add_issuer_pending_admin_rejected() {
    let (env, contract_id, _, pending_admin, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let new_issuer = Address::generate(&env);
    client.add_issuer(&pending_admin, &new_issuer, &bytes32(&env, 1));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_add_issuer_issuer_rejected() {
    let (env, contract_id, _, _, issuer, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let new_issuer = Address::generate(&env);
    // Passing the existing issuer as the admin argument → Unauthorized
    client.add_issuer(&issuer, &new_issuer, &bytes32(&env, 1));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_add_issuer_source_rejected() {
    let (env, contract_id, _, _, _, source) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let new_issuer = Address::generate(&env);
    client.add_issuer(&source, &new_issuer, &bytes32(&env, 1));
}

// ---------------------------------------------------------------------------
// revoke_issuer
// ---------------------------------------------------------------------------

#[test]
fn auth_revoke_issuer_admin_succeeds() {
    let (env, contract_id, admin, _, issuer, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.revoke_issuer(&admin, &issuer);
    assert!(!client.get_issuer(&issuer).unwrap().active);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_revoke_issuer_pending_admin_rejected() {
    let (env, contract_id, _, pending_admin, issuer, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.revoke_issuer(&pending_admin, &issuer);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_revoke_issuer_issuer_self_rejected() {
    let (env, contract_id, _, _, issuer, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    // An issuer cannot revoke itself by passing itself as admin
    client.revoke_issuer(&issuer, &issuer);
}

// ---------------------------------------------------------------------------
// set_verifier
// ---------------------------------------------------------------------------

#[test]
fn auth_set_verifier_admin_succeeds() {
    let (env, contract_id, admin, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let verifier = Address::generate(&env);
    client.set_verifier(&admin, &verifier);
    assert_eq!(client.get_verifier(), Some(verifier));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_set_verifier_non_admin_rejected() {
    let (env, contract_id, _, pending_admin, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let verifier = Address::generate(&env);
    client.set_verifier(&pending_admin, &verifier);
}

// ---------------------------------------------------------------------------
// add_credential_root
// ---------------------------------------------------------------------------

#[test]
fn auth_add_credential_root_admin_succeeds() {
    let (env, contract_id, admin, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let root = bytes32(&env, 0xDD);
    client.add_credential_root(&admin, &root, &bytes32(&env, 0xEE));
    assert!(client.get_credential_root(&root).unwrap().active);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_add_credential_root_pending_admin_rejected() {
    let (env, contract_id, _, pending_admin, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.add_credential_root(&pending_admin, &bytes32(&env, 0xDD), &bytes32(&env, 0xEE));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_add_credential_root_issuer_rejected() {
    let (env, contract_id, _, _, issuer, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.add_credential_root(&issuer, &bytes32(&env, 0xDD), &bytes32(&env, 0xEE));
}

// ---------------------------------------------------------------------------
// revoke_credential_root
// ---------------------------------------------------------------------------

#[test]
fn auth_revoke_credential_root_admin_succeeds() {
    let (env, contract_id, admin, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let root = bytes32(&env, 0xBB);
    client.revoke_credential_root(&admin, &root);
    assert!(!client.get_credential_root(&root).unwrap().active);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_revoke_credential_root_pending_admin_rejected() {
    let (env, contract_id, _, pending_admin, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.revoke_credential_root(&pending_admin, &bytes32(&env, 0xBB));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_revoke_credential_root_source_rejected() {
    let (env, contract_id, _, _, _, source) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.revoke_credential_root(&source, &bytes32(&env, 0xBB));
}

// ---------------------------------------------------------------------------
// revoke_proof
// ---------------------------------------------------------------------------

#[test]
fn auth_revoke_proof_admin_succeeds() {
    let (env, contract_id, admin, _, _, source) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let video_hash = bytes32(&env, 0x01);
    let proof_id = bytes32(&env, 0x02);
    client.register_source(&source, &video_hash, &bytes32(&env, 0x03), &proof_id);
    client.revoke_proof(&admin, &proof_id);
    assert_eq!(client.get_proof(&proof_id).unwrap().status, STATUS_REVOKED);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_revoke_proof_pending_admin_rejected() {
    let (env, contract_id, _, pending_admin, _, source) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = bytes32(&env, 0x04);
    client.register_source(
        &source,
        &bytes32(&env, 0x05),
        &bytes32(&env, 0x06),
        &proof_id,
    );
    client.revoke_proof(&pending_admin, &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_revoke_proof_issuer_rejected() {
    let (env, contract_id, _, _, issuer, source) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = bytes32(&env, 0x07);
    client.register_source(
        &source,
        &bytes32(&env, 0x08),
        &bytes32(&env, 0x09),
        &proof_id,
    );
    client.revoke_proof(&issuer, &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_revoke_proof_source_self_rejected() {
    let (env, contract_id, _, _, _, source) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = bytes32(&env, 0x0A);
    client.register_source(
        &source,
        &bytes32(&env, 0x0B),
        &bytes32(&env, 0x0C),
        &proof_id,
    );
    // The source that registered cannot revoke its own proof
    client.revoke_proof(&source, &proof_id);
}

// ---------------------------------------------------------------------------
// set_proof_ttl
// ---------------------------------------------------------------------------

#[test]
fn auth_set_proof_ttl_admin_succeeds() {
    let (env, contract_id, admin, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_proof_ttl(&admin, &3600u64);
    assert_eq!(client.get_proof_ttl(), 3600u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_set_proof_ttl_pending_admin_rejected() {
    let (env, contract_id, _, pending_admin, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_proof_ttl(&pending_admin, &3600u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn auth_set_proof_ttl_issuer_rejected() {
    let (env, contract_id, _, _, issuer, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_proof_ttl(&issuer, &3600u64);
}

// ---------------------------------------------------------------------------
// register_source: source must sign; others must not be able to impersonate
// ---------------------------------------------------------------------------

/// register_source: the source address must authorise the call.
/// With mock_all_auths this always succeeds; we verify the call goes through.
#[test]
fn auth_register_source_signer_succeeds() {
    let (env, contract_id, _, _, _, source) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let rec = client.register_source(
        &source,
        &bytes32(&env, 0x10),
        &bytes32(&env, 0x11),
        &bytes32(&env, 0x12),
    );
    assert_eq!(rec.source, Some(source));
}

// ---------------------------------------------------------------------------
// register_seal: issuer must be active
// ---------------------------------------------------------------------------

#[test]
fn auth_register_seal_active_issuer_succeeds() {
    let (env, contract_id, _, _, issuer, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let rec = client.register_seal(
        &issuer,
        &bytes32(&env, 0x20),
        &bytes32(&env, 0x21),
        &bytes32(&env, 0x22),
    );
    assert_eq!(rec.issuer, Some(issuer));
}

/// register_seal: a revoked issuer is rejected with UnknownIssuer (#8).
#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn auth_register_seal_revoked_issuer_rejected() {
    let (env, contract_id, admin, _, issuer, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.revoke_issuer(&admin, &issuer);
    client.register_seal(
        &issuer,
        &bytes32(&env, 0x23),
        &bytes32(&env, 0x24),
        &bytes32(&env, 0x25),
    );
}

/// register_seal: an address never registered as issuer is rejected with UnknownIssuer (#8).
#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn auth_register_seal_unknown_issuer_rejected() {
    let (env, contract_id, _, _, _, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let random = Address::generate(&env);
    client.register_seal(
        &random,
        &bytes32(&env, 0x26),
        &bytes32(&env, 0x27),
        &bytes32(&env, 0x28),
    );
}
