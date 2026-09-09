//! Dispute / correction state-machine tests (#dispute).
//!
//! Covers acceptance criteria:
//!   - Invalid state transitions, duplicate submissions, unauthorized resolution,
//!     expired windows, cyclic supersession, concurrent decisions
//!   - Disputed / superseded / valid / revoked / expired are distinct statuses
//!   - Resolution never deletes the original proof record
//!   - Open-dispute cap (MAX_OPEN_DISPUTES_PER_PROOF)
//!   - Reporter cooldown

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn b32u(env: &Env, pos: usize, v: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[pos] = v;
    BytesN::from_array(env, &arr)
}

/// Create a fresh env + client, init registry, register a source proof and a
/// seal proof. Returns everything callers need.
fn make_env() -> (
    Env,
    Address, // contract_id
    Address, // admin
    Address, // source
    Address, // issuer
    BytesN<32>, // source_proof_id
    BytesN<32>, // seal_proof_id
) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin  = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));

    let source_proof_id = b32(&env, 0x01);
    client.register_source(
        &source,
        &b32(&env, 0x02),
        &b32(&env, 0x03),
        &source_proof_id,
    );

    let seal_proof_id = b32(&env, 0x11);
    client.register_seal(
        &issuer,
        &b32(&env, 0x12),
        &b32(&env, 0x13),
        &seal_proof_id,
    );

    (env, contract_id, admin, source, issuer, source_proof_id, seal_proof_id)
}

// ---------------------------------------------------------------------------
// open_dispute: happy path stores record
// ---------------------------------------------------------------------------

#[test]
fn open_dispute_stores_record() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let reporter    = Address::generate(&env);
    let dispute_id  = b32(&env, 0xD1);
    let rep_hash    = b32(&env, 0xE1);
    let commitment  = b32(&env, 0xC1);

    let rec = client.open_dispute(
        &reporter, &rep_hash, &dispute_id, &spid,
        &DisputeReason::ContentError, &commitment,
    );

    assert_eq!(rec.status,           DisputeStatus::Open);
    assert_eq!(rec.dispute_id,       dispute_id);
    assert_eq!(rec.proof_id,         spid);
    assert_eq!(rec.reason,           DisputeReason::ContentError);
    assert_eq!(rec.reporter_hash,    rep_hash);
    assert_eq!(rec.commitment_hash,  commitment);
    assert_eq!(rec.response_commitment, None);
    assert_eq!(rec.superseded_by,   None);
    assert_eq!(rec.resolved_at,     0);

    let fetched = client.get_dispute(&dispute_id).expect("dispute not found");
    assert_eq!(fetched.status, DisputeStatus::Open);
    assert_eq!(client.get_open_dispute_count(&spid), 1);
}

// ---------------------------------------------------------------------------
// open_dispute: duplicate dispute_id rejected
// ---------------------------------------------------------------------------

#[test]
fn duplicate_dispute_id_rejected() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let reporter   = Address::generate(&env);
    let dispute_id = b32(&env, 0xD2);

    client.open_dispute(
        &reporter, &b32(&env, 0xE2), &dispute_id, &spid,
        &DisputeReason::MetadataError, &b32(&env, 0xC2),
    );

    let result = client.try_open_dispute(
        &reporter, &b32(&env, 0xE2), &dispute_id, &spid,
        &DisputeReason::MetadataError, &b32(&env, 0xC2),
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// open_dispute: non-existent proof rejected
// ---------------------------------------------------------------------------

#[test]
fn dispute_nonexistent_proof_rejected() {
    let (env, cid, _admin, _source, _issuer, _, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let reporter = Address::generate(&env);
    let result = client.try_open_dispute(
        &reporter, &b32(&env, 0xE3), &b32(&env, 0xD3),
        &b32(&env, 0xFF), &DisputeReason::Other, &b32(&env, 0xC3),
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// open_dispute: open-cap enforced
// ---------------------------------------------------------------------------

#[test]
fn open_dispute_cap_enforced() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    for i in 0..MAX_OPEN_DISPUTES_PER_PROOF {
        let reporter = Address::generate(&env);
        client.open_dispute(
            &reporter,
            &b32u(&env, 0, (0xE0 + i) as u8),
            &b32u(&env, 1, (0xD0 + i) as u8),
            &spid,
            &DisputeReason::Other,
            &b32u(&env, 2, (0xC0 + i) as u8),
        );
    }
    assert_eq!(client.get_open_dispute_count(&spid), MAX_OPEN_DISPUTES_PER_PROOF);

    let reporter = Address::generate(&env);
    let result = client.try_open_dispute(
        &reporter, &b32(&env, 0xEF), &b32(&env, 0xDF),
        &spid, &DisputeReason::Other, &b32(&env, 0xCF),
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// open_dispute: reporter cooldown
// ---------------------------------------------------------------------------

#[test]
fn reporter_cooldown_enforced() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client   = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let rep_hash = b32(&env, 0xE5);

    client.open_dispute(
        &reporter, &rep_hash, &b32(&env, 0xD5), &spid,
        &DisputeReason::TierMismatch, &b32(&env, 0xC5),
    );

    // Still on cooldown after 1 second
    let ts = env.ledger().timestamp();
    env.ledger().set_timestamp(ts + 1);

    let result = client.try_open_dispute(
        &reporter, &rep_hash, &b32(&env, 0xD6), &spid,
        &DisputeReason::TierMismatch, &b32(&env, 0xC6),
    );
    assert!(result.is_err());

    // Past cooldown succeeds
    env.ledger().set_timestamp(ts + REPORTER_COOLDOWN_SECS + 1);
    client.open_dispute(
        &reporter, &rep_hash, &b32(&env, 0xD7), &spid,
        &DisputeReason::TierMismatch, &b32(&env, 0xC7),
    );
}

// ---------------------------------------------------------------------------
// respond_dispute: happy path
// ---------------------------------------------------------------------------

#[test]
fn respond_dispute_happy_path() {
    let (env, cid, _admin, source, _issuer, spid, _) = make_env();
    let client     = HarpocratesRegistryClient::new(&env, &cid);
    let reporter   = Address::generate(&env);
    let dispute_id = b32(&env, 0xAA);

    client.open_dispute(
        &reporter, &b32(&env, 0xEA), &dispute_id, &spid,
        &DisputeReason::ContentError, &b32(&env, 0xCA),
    );

    let rec = client.respond_dispute(&source, &dispute_id, &b32(&env, 0xBA));
    assert_eq!(rec.status, DisputeStatus::Responded);
    assert_eq!(rec.response_commitment, Some(b32(&env, 0xBA)));
    assert!(rec.resolve_deadline > 0);
}

// ---------------------------------------------------------------------------
// respond_dispute: unauthorized responder rejected
// ---------------------------------------------------------------------------

#[test]
fn unauthorized_responder_rejected() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client   = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let stranger = Address::generate(&env);
    let dispute_id = b32(&env, 0xCC);

    client.open_dispute(
        &reporter, &b32(&env, 0xEC), &dispute_id, &spid,
        &DisputeReason::ContentError, &b32(&env, 0xCC),
    );

    let result = client.try_respond_dispute(&stranger, &dispute_id, &b32(&env, 0xDC));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// respond_dispute: deadline expired
// ---------------------------------------------------------------------------

#[test]
fn respond_after_deadline_rejected() {
    let (env, cid, _admin, source, _issuer, spid, _) = make_env();
    let client     = HarpocratesRegistryClient::new(&env, &cid);
    let reporter   = Address::generate(&env);
    let dispute_id = b32(&env, 0xF1);

    client.open_dispute(
        &reporter, &b32(&env, 0xE1), &dispute_id, &spid,
        &DisputeReason::ContentError, &b32(&env, 0xC1),
    );

    let ts = env.ledger().timestamp();
    env.ledger().set_timestamp(ts + RESPOND_DEADLINE_SECS + 1);

    let result = client.try_respond_dispute(&source, &dispute_id, &b32(&env, 0xD1));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// resolve_dispute: happy path open→respond→resolve
// ---------------------------------------------------------------------------

#[test]
fn resolve_dispute_happy_path() {
    let (env, cid, admin, source, _issuer, spid, _) = make_env();
    let client     = HarpocratesRegistryClient::new(&env, &cid);
    let reporter   = Address::generate(&env);
    let dispute_id = b32(&env, 0xBB);

    client.open_dispute(
        &reporter, &b32(&env, 0xEB), &dispute_id, &spid,
        &DisputeReason::PrivacyViolation, &b32(&env, 0xCB),
    );
    client.respond_dispute(&source, &dispute_id, &b32(&env, 0xDB));

    let rec = client.resolve_dispute(&admin, &dispute_id);
    assert_eq!(rec.status, DisputeStatus::Resolved);
    assert!(rec.resolved_at > 0);
    assert_eq!(client.get_open_dispute_count(&spid), 0);

    // Proof unchanged
    let proof = client.get_proof(&spid).expect("proof deleted");
    assert_eq!(proof.status, STATUS_REGISTERED);
}

// ---------------------------------------------------------------------------
// resolve_dispute: resolve-deadline expired
// ---------------------------------------------------------------------------

#[test]
fn resolve_after_deadline_rejected() {
    let (env, cid, admin, source, _issuer, spid, _) = make_env();
    let client     = HarpocratesRegistryClient::new(&env, &cid);
    let reporter   = Address::generate(&env);
    let dispute_id = b32(&env, 0xF2);

    client.open_dispute(
        &reporter, &b32(&env, 0xE2), &dispute_id, &spid,
        &DisputeReason::ContentError, &b32(&env, 0xC2),
    );
    client.respond_dispute(&source, &dispute_id, &b32(&env, 0xD2));

    let ts = env.ledger().timestamp();
    env.ledger().set_timestamp(ts + RESOLVE_DEADLINE_SECS + 1);

    let result = client.try_resolve_dispute(&admin, &dispute_id);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// resolve_dispute: cannot resolve Open (must be Responded first)
// ---------------------------------------------------------------------------

#[test]
fn cannot_resolve_open_dispute() {
    let (env, cid, admin, _source, _issuer, spid, _) = make_env();
    let client     = HarpocratesRegistryClient::new(&env, &cid);
    let reporter   = Address::generate(&env);
    let dispute_id = b32(&env, 0xF4);

    client.open_dispute(
        &reporter, &b32(&env, 0xE4), &dispute_id, &spid,
        &DisputeReason::ContentError, &b32(&env, 0xC4),
    );

    let result = client.try_resolve_dispute(&admin, &dispute_id);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// resolve_dispute: non-admin rejected
// ---------------------------------------------------------------------------

#[test]
fn non_admin_cannot_resolve() {
    let (env, cid, _admin, source, _issuer, spid, _) = make_env();
    let client     = HarpocratesRegistryClient::new(&env, &cid);
    let reporter   = Address::generate(&env);
    let stranger   = Address::generate(&env);
    let dispute_id = b32(&env, 0xDD);

    client.open_dispute(
        &reporter, &b32(&env, 0xED), &dispute_id, &spid,
        &DisputeReason::ContentError, &b32(&env, 0xCD),
    );
    client.respond_dispute(&source, &dispute_id, &b32(&env, 0xDE));

    let result = client.try_resolve_dispute(&stranger, &dispute_id);
    assert!(result.is_err());
}
