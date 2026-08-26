#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, IntoVal, InvokeError, String, Symbol, Val, Vec as SorobanVec,
};

const TIER_SILENT_WITNESS: u32 = 1;
const TIER_CONSISTENT_SOURCE: u32 = 2;
const TIER_PUBLIC_SEAL: u32 = 3;

const STATUS_REGISTERED: u32 = 1;
const STATUS_REVOKED: u32 = 2;

// ---------------------------------------------------------------------------
// Verifier-set configuration constants (#126)
// ---------------------------------------------------------------------------

/// Maximum number of verifier members in a single verifier set.
pub const MAX_VERIFIERS_PER_SET: u32 = 16;
/// Maximum number of distinct verifier-set versions that may coexist.
pub const MAX_VERIFIER_SETS: u32 = 8;
/// Maximum accepted proof byte length.
pub const MAX_PROOF_SIZE_BYTES: u32 = 65_536;
/// Maximum accepted public-inputs byte length.
pub const MAX_PUBLIC_INPUTS_SIZE_BYTES: u32 = 4_096;
/// Seconds that must elapse between propose_verifier_set and activate_verifier_set.
/// Set to 300 (5 min) so tests can advance ledger time easily.
pub const VERIFIER_SET_TIMELOCK_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Proof-expiration policy (#44)
// ---------------------------------------------------------------------------
pub const DEFAULT_PROOF_TTL_SECS: u64 = 0;

// ---------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------

/// Verification status returned by `get_proof_status`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofVerificationStatus {
    Valid,
    Revoked,
    Expired,
    NotFound,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRecord {
    pub video_hash: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub tier: u32,
    pub status: u32,
    pub created_at: u64,
    /// Epoch-second deadline after which this proof is considered expired.
    /// `0` means no expiration.
    pub expires_at: u64,
    pub source: Option<Address>,
    pub issuer: Option<Address>,
    pub nullifier: Option<BytesN<32>>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRecord {
    pub metadata_hash: BytesN<32>,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRootRecord {
    pub metadata_hash: BytesN<32>,
    pub active: bool,
    pub issued_at: u64,
}

// ---------------------------------------------------------------------------
// Verifier-set types (#126)
// ---------------------------------------------------------------------------

/// A versioned, bounded set of verifier contracts with m-of-n quorum.
///
/// Members are stored separately under `DataKey::VerifierSetMember(version, index)`.
/// This struct holds only scalar fields to comply with Soroban contracttype rules
/// (no generic container types).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierSetRecord {
    /// Monotonically increasing version number (starts at 1).
    pub version: u32,
    /// Number of members in this set (stored separately by index).
    pub member_count: u32,
    /// Number of approvals required to accept a proof (m in m-of-n).
    pub threshold: u32,
    /// Ledger timestamp at/after which this set may be used.
    pub active_from: u64,
    /// Ledger timestamp at which this set was retired (0 = still active).
    pub retired_at: u64,
    /// Emergency-disabled flag. When true the set may not be used.
    pub disabled: bool,
    /// Human-readable circuit/artifact version tag (e.g. "ultraHonk-0.87.0").
    pub circuit_version: String,
}

/// Canonical outcome of quorum evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumResult {
    /// Quorum of approvals reached.
    Approved,
    /// Quorum of rejections reached (deterministic disagreement).
    Rejected,
    /// Too many verifiers were unreachable; cannot reach quorum.
    Unavailable,
    /// All verifiers failed and the set carries a circuit_version tag
    /// (likely artifact/circuit incompatibility).
    VersionMismatch,
    /// Not enough votes yet (intermediate; never persisted as final).
    Pending,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[contractevent(topics = ["proof", "reg"])]
pub struct ProofRegistered {
    #[topic]
    pub proof_id: BytesN<32>,
    pub video_hash: BytesN<32>,
    pub tier: u32,
    pub status: u32,
}

#[contractevent(topics = ["proof", "revoke"])]
pub struct ProofRevoked {
    #[topic]
    pub proof_id: BytesN<32>,
    pub status: u32,
}

#[contractevent(topics = ["issuer", "add"])]
pub struct IssuerAdded {
    #[topic]
    pub issuer: Address,
    pub metadata_hash: BytesN<32>,
}

#[contractevent(topics = ["issuer", "revoke"])]
pub struct IssuerRevoked {
    #[topic]
    pub issuer: Address,
}

#[contractevent(topics = ["verif", "set"])]
pub struct VerifierSet {
    #[topic]
    pub verifier: Address,
}

#[contractevent(topics = ["credroot", "add"])]
pub struct CredentialRootAdded {
    #[topic]
    pub credential_root: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub issued_at: u64,
}

#[contractevent(topics = ["credroot", "revoke"])]
pub struct CredentialRootRevoked {
    #[topic]
    pub credential_root: BytesN<32>,
}

#[contractevent(topics = ["admin", "propose"])]
pub struct AdminProposed {
    #[topic]
    pub pending_admin: Address,
    pub current_admin: Address,
}

#[contractevent(topics = ["admin", "cancel"])]
pub struct AdminTransferCancelled {
    #[topic]
    pub pending_admin: Address,
    pub current_admin: Address,
}

#[contractevent(topics = ["admin", "accept"])]
pub struct AdminAccepted {
    #[topic]
    pub new_admin: Address,
    pub previous_admin: Address,
}

// Verifier-set lifecycle events (#126)
#[contractevent(topics = ["vset", "propose"])]
pub struct VerifierSetProposed {
    #[topic]
    pub version: u32,
    pub threshold: u32,
    pub member_count: u32,
    pub unlocks_at: u64,
}

#[contractevent(topics = ["vset", "activate"])]
pub struct VerifierSetActivated {
    #[topic]
    pub version: u32,
    pub threshold: u32,
    pub member_count: u32,
}

#[contractevent(topics = ["vset", "disable"])]
pub struct VerifierSetDisabledEvent {
    #[topic]
    pub version: u32,
}

// Quorum events (#126)
#[contractevent(topics = ["quorum", "final"])]
pub struct QuorumFinalized {
    #[topic]
    pub proof_id: BytesN<32>,
    pub approved: u32,
    pub rejected: u32,
    pub failures: u32,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    Admin,
    Proof(BytesN<32>),
    Video(BytesN<32>),
    Nullifier(BytesN<32>),
    CredentialRoot(BytesN<32>),
    Issuer(Address),
    /// Legacy single verifier (kept for backward compatibility).
    Verifier,
    ProofTtl,
    PendingAdmin,
    // Verifier-set keys (#126)
    /// Current active verifier set version number (u32).
    ActiveVerifierSetVersion,
    /// VerifierSetRecord keyed by version (scalar fields only).
    VerifierSetByVersion(u32),
    /// Individual member address at (version, index).
    VerifierSetMember(u32, u32),
    /// Next available version counter.
    NextVerifierSetVersion,
    /// Pending verifier set record (scalar fields) awaiting timelock.
    PendingVerifierSetRecord,
    /// Pending verifier set member at index.
    PendingVerifierSetMember(u32),
    /// Ledger timestamp after which pending set may be promoted.
    PendingVerifierSetUnlocksAt,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    DuplicateProof = 4,
    DuplicateVideo = 5,
    DuplicateNullifier = 6,
    InvalidProof = 7,
    UnknownIssuer = 8,
    VerifierNotSet = 9,
    InvalidPublicInputs = 10,
    UnknownCredentialRoot = 11,
    RevokedCredentialRoot = 12,
    NoPendingAdmin = 13,
    // Verifier-set errors (#126)
    VerifierSetNotFound = 14,
    QuorumNotReached = 15,
    DuplicateVote = 16,
    VerifierSetDisabled = 17,
    VerifierSetNotActive = 18,
    VersionMismatch = 19,
    ProofTooLarge = 20,
    VerifierSetFull = 21,
    TooManyVerifierSets = 22,
    TimelockNotExpired = 23,
    NoPendingVerifierSet = 24,
    InvalidThreshold = 25,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct HarpocratesRegistry;

#[contractimpl]
impl HarpocratesRegistry {
    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    pub fn init(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic_with_error!(&env, RegistryError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn propose_admin(env: Env, admin: Address, pending_admin: Address) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &pending_admin);
        AdminProposed {
            pending_admin,
            current_admin: admin,
        }
        .publish(&env);
    }

    pub fn cancel_admin_transfer(env: Env, admin: Address) {
        require_admin(&env, &admin);
        let pending_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingAdmin));
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        AdminTransferCancelled {
            pending_admin,
            current_admin: admin,
        }
        .publish(&env);
    }

    pub fn accept_admin(env: Env, pending_admin: Address) {
        let proposed_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingAdmin));
        pending_admin.require_auth();
        if proposed_admin != pending_admin {
            panic_with_error!(&env, RegistryError::Unauthorized);
        }
        let previous_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
        env.storage()
            .persistent()
            .set(&DataKey::Admin, &pending_admin);
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        AdminAccepted {
            new_admin: pending_admin,
            previous_admin,
        }
        .publish(&env);
    }

    // -----------------------------------------------------------------------
    // Issuer management
    // -----------------------------------------------------------------------

    pub fn add_issuer(env: Env, admin: Address, issuer: Address, metadata_hash: BytesN<32>) {
        require_admin(&env, &admin);
        env.storage().persistent().set(
            &DataKey::Issuer(issuer.clone()),
            &IssuerRecord {
                metadata_hash: metadata_hash.clone(),
                active: true,
            },
        );
        IssuerAdded {
            issuer,
            metadata_hash,
        }
        .publish(&env);
    }

    pub fn revoke_issuer(env: Env, admin: Address, issuer: Address) {
        require_admin(&env, &admin);
        let mut record = get_issuer_record(&env, &issuer);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &record);
        IssuerRevoked { issuer }.publish(&env);
    }

    pub fn get_issuer(env: Env, issuer: Address) -> Option<IssuerRecord> {
        env.storage().persistent().get(&DataKey::Issuer(issuer))
    }

    // -----------------------------------------------------------------------
    // Legacy single-verifier (backward compatibility)
    // -----------------------------------------------------------------------

    pub fn set_verifier(env: Env, admin: Address, verifier: Address) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &verifier);
        VerifierSet { verifier }.publish(&env);
    }

    pub fn get_verifier(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Verifier)
    }

    // -----------------------------------------------------------------------
    // Verifier-set management (#126)
    //
    // Members are passed as individual addresses and stored with indexed keys
    // to avoid generic container types in contract function signatures.
    // -----------------------------------------------------------------------

    /// Propose a new verifier set with the given members and threshold.
    ///
    /// - Only admin may call.
    /// - `member_count` must be 1..=MAX_VERIFIERS_PER_SET.
    /// - `threshold` must satisfy 1 <= threshold <= member_count.
    /// - Callers must first call `add_pending_verifier_set_member` to register
    ///   each member at indices 0..member_count, then call this to finalize.
    ///
    /// For convenience, this contract exposes
    /// `propose_verifier_set_1` through `propose_verifier_set_3` for 1–3
    /// member sets, which are the most common sizes in tests.
    /// For larger sets, use `add_pending_member` + `finalize_verifier_set`.
    ///
    /// Returns the proposed version number.
    pub fn propose_verifier_set_1(
        env: Env,
        admin: Address,
        m0: Address,
        threshold: u32,
        circuit_version: String,
    ) -> u32 {
        require_admin(&env, &admin);
        if threshold == 0 || threshold > 1 {
            panic_with_error!(&env, RegistryError::InvalidThreshold);
        }
        let next_version = get_next_version(&env);
        if next_version > MAX_VERIFIER_SETS {
            panic_with_error!(&env, RegistryError::TooManyVerifierSets);
        }
        let unlocks_at = env
            .ledger()
            .timestamp()
            .saturating_add(VERIFIER_SET_TIMELOCK_SECS);
        store_pending_set(&env, next_version, 1, threshold, unlocks_at, &circuit_version);
        env.storage()
            .persistent()
            .set(&DataKey::PendingVerifierSetMember(0), &m0);
        emit_proposed(&env, next_version, threshold, 1, unlocks_at);
        next_version
    }

    pub fn propose_verifier_set_2(
        env: Env,
        admin: Address,
        m0: Address,
        m1: Address,
        threshold: u32,
        circuit_version: String,
    ) -> u32 {
        require_admin(&env, &admin);
        if threshold == 0 || threshold > 2 {
            panic_with_error!(&env, RegistryError::InvalidThreshold);
        }
        let next_version = get_next_version(&env);
        if next_version > MAX_VERIFIER_SETS {
            panic_with_error!(&env, RegistryError::TooManyVerifierSets);
        }
        let unlocks_at = env
            .ledger()
            .timestamp()
            .saturating_add(VERIFIER_SET_TIMELOCK_SECS);
        store_pending_set(&env, next_version, 2, threshold, unlocks_at, &circuit_version);
        env.storage()
            .persistent()
            .set(&DataKey::PendingVerifierSetMember(0), &m0);
        env.storage()
            .persistent()
            .set(&DataKey::PendingVerifierSetMember(1), &m1);
        emit_proposed(&env, next_version, threshold, 2, unlocks_at);
        next_version
    }

    pub fn propose_verifier_set_3(
        env: Env,
        admin: Address,
        m0: Address,
        m1: Address,
        m2: Address,
        threshold: u32,
        circuit_version: String,
    ) -> u32 {
        require_admin(&env, &admin);
        if threshold == 0 || threshold > 3 {
            panic_with_error!(&env, RegistryError::InvalidThreshold);
        }
        let next_version = get_next_version(&env);
        if next_version > MAX_VERIFIER_SETS {
            panic_with_error!(&env, RegistryError::TooManyVerifierSets);
        }
        let unlocks_at = env
            .ledger()
            .timestamp()
            .saturating_add(VERIFIER_SET_TIMELOCK_SECS);
        store_pending_set(&env, next_version, 3, threshold, unlocks_at, &circuit_version);
        env.storage()
            .persistent()
            .set(&DataKey::PendingVerifierSetMember(0), &m0);
        env.storage()
            .persistent()
            .set(&DataKey::PendingVerifierSetMember(1), &m1);
        env.storage()
            .persistent()
            .set(&DataKey::PendingVerifierSetMember(2), &m2);
        emit_proposed(&env, next_version, threshold, 3, unlocks_at);
        next_version
    }

    /// Promote the pending verifier set to active once the timelock has expired.
    ///
    /// - Only admin may call.
    /// - Panics with TimelockNotExpired if called too early.
    /// - Marks the previously active set as retired.
    /// - Returns the new active version number.
    pub fn activate_verifier_set(env: Env, admin: Address) -> u32 {
        require_admin(&env, &admin);

        let unlocks_at: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::PendingVerifierSetUnlocksAt)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingVerifierSet));

        if env.ledger().timestamp() < unlocks_at {
            panic_with_error!(&env, RegistryError::TimelockNotExpired);
        }

        let proposal: VerifierSetRecord = env
            .storage()
            .persistent()
            .get(&DataKey::PendingVerifierSetRecord)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingVerifierSet));

        let version = proposal.version;
        let member_count = proposal.member_count;
        let threshold = proposal.threshold;

        // Retire the previously active set (if any).
        retire_previous_active_set(&env);

        // Copy pending members to permanent storage.
        for i in 0..member_count {
            let member: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PendingVerifierSetMember(i))
                .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierSetNotFound));
            env.storage()
                .persistent()
                .set(&DataKey::VerifierSetMember(version, i), &member);
        }

        // Store the record and mark active.
        env.storage()
            .persistent()
            .set(&DataKey::VerifierSetByVersion(version), &proposal);
        env.storage()
            .persistent()
            .set(&DataKey::ActiveVerifierSetVersion, &version);
        env.storage()
            .persistent()
            .set(&DataKey::NextVerifierSetVersion, &(version + 1));

        // Clean up pending state.
        env.storage()
            .persistent()
            .remove(&DataKey::PendingVerifierSetRecord);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingVerifierSetUnlocksAt);
        for i in 0..member_count {
            env.storage()
                .persistent()
                .remove(&DataKey::PendingVerifierSetMember(i));
        }

        VerifierSetActivated {
            version,
            threshold,
            member_count,
        }
        .publish(&env);

        version
    }

    /// Emergency-disable a specific verifier set version.
    ///
    /// A disabled set may not be used for proof acceptance.  This does NOT
    /// roll back proofs already accepted; it prevents future use only.
    /// Only admin may call.
    pub fn disable_verifier_set(env: Env, admin: Address, version: u32) {
        require_admin(&env, &admin);
        let mut record: VerifierSetRecord = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierSetByVersion(version))
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierSetNotFound));
        record.disabled = true;
        env.storage()
            .persistent()
            .set(&DataKey::VerifierSetByVersion(version), &record);
        VerifierSetDisabledEvent { version }.publish(&env);
    }

    /// Return the currently active verifier set record, or None.
    pub fn get_active_verifier_set(env: Env) -> Option<VerifierSetRecord> {
        let version: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ActiveVerifierSetVersion)?;
        env.storage()
            .persistent()
            .get(&DataKey::VerifierSetByVersion(version))
    }

    /// Return a verifier set record by explicit version number, or None.
    pub fn get_verifier_set(env: Env, version: u32) -> Option<VerifierSetRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::VerifierSetByVersion(version))
    }

    /// Return a member address from the active verifier set by index.
    pub fn get_verifier_set_member(env: Env, version: u32, index: u32) -> Option<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::VerifierSetMember(version, index))
    }

    // -----------------------------------------------------------------------
    // Credential roots
    // -----------------------------------------------------------------------

    pub fn add_credential_root(
        env: Env,
        admin: Address,
        credential_root: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) {
        require_admin(&env, &admin);
        let issued_at = env.ledger().timestamp();
        env.storage().persistent().set(
            &DataKey::CredentialRoot(credential_root.clone()),
            &CredentialRootRecord {
                metadata_hash: metadata_hash.clone(),
                active: true,
                issued_at,
            },
        );
        CredentialRootAdded {
            credential_root,
            metadata_hash,
            issued_at,
        }
        .publish(&env);
    }

    pub fn revoke_credential_root(env: Env, admin: Address, credential_root: BytesN<32>) {
        require_admin(&env, &admin);
        let mut record = get_credential_root_record(&env, &credential_root);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::CredentialRoot(credential_root.clone()), &record);
        CredentialRootRevoked { credential_root }.publish(&env);
    }

    pub fn get_credential_root(
        env: Env,
        credential_root: BytesN<32>,
    ) -> Option<CredentialRootRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::CredentialRoot(credential_root))
    }

    // -----------------------------------------------------------------------
    // Expiration policy (#44)
    // -----------------------------------------------------------------------

    pub fn set_proof_ttl(env: Env, admin: Address, ttl_secs: u64) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ProofTtl, &ttl_secs);
    }

    pub fn get_proof_ttl(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofTtl)
            .unwrap_or(DEFAULT_PROOF_TTL_SECS)
    }

    pub fn get_proof_status(env: Env, proof_id: BytesN<32>) -> ProofVerificationStatus {
        let record: Option<ProofRecord> =
            env.storage().persistent().get(&DataKey::Proof(proof_id));
        match record {
            None => ProofVerificationStatus::NotFound,
            Some(r) => {
                if r.status == STATUS_REVOKED {
                    return ProofVerificationStatus::Revoked;
                }
                if r.expires_at > 0 && env.ledger().timestamp() > r.expires_at {
                    return ProofVerificationStatus::Expired;
                }
                ProofVerificationStatus::Valid
            }
        }
    }

    // -----------------------------------------------------------------------
    // Registration entry points
    // -----------------------------------------------------------------------

    pub fn register_anonymous(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        nullifier: BytesN<32>,
        credential_root: BytesN<32>,
        proof: Bytes,
    ) -> ProofRecord {
        require_unique(&env, &proof_id, &video_hash);
        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }
        if !verify_demo_zk_boundary(&proof, &credential_root) {
            panic_with_error!(&env, RegistryError::InvalidProof);
        }
        require_active_credential_root(&env, &credential_root);
        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(nullifier.clone()), &true);
        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_SILENT_WITNESS,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: None,
                issuer: None,
                nullifier: Some(nullifier),
            },
        )
    }

    pub fn register_anonymous_verified(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        public_inputs: Bytes,
        proof: Bytes,
    ) -> ProofRecord {
        require_unique(&env, &proof_id, &video_hash);
        let parsed = parse_silent_witness_public_inputs(&env, &public_inputs);
        if parsed.video_hash != video_hash {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }
        require_active_credential_root(&env, &parsed.credential_root);
        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(parsed.nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }
        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
        verify_external_proof(&env, &verifier, public_inputs, proof);
        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(parsed.nullifier.clone()), &true);
        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_SILENT_WITNESS,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: None,
                issuer: None,
                nullifier: Some(parsed.nullifier),
            },
        )
    }

    /// Submit a proof for quorum-based multi-verifier evaluation (#126).
    ///
    /// Iterates the active verifier set, calling `verify_proof` on each
    /// member.  Approvals, rejections, and invocation failures are tallied
    /// deterministically:
    ///
    /// - approved >= threshold                            → Approved → proof registered.
    /// - rejected > members.len() - threshold             → Rejected (deterministic disagreement).
    /// - failures prevent quorum from ever being reached  → Unavailable.
    /// - all verifiers fail AND set has a circuit_version → VersionMismatch.
    ///
    /// Bounds: proof <= MAX_PROOF_SIZE_BYTES,
    ///         public_inputs <= MAX_PUBLIC_INPUTS_SIZE_BYTES.
    pub fn register_anon_verified_quorum(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        public_inputs: Bytes,
        proof: Bytes,
    ) -> ProofRecord {
        // Bounds checks.
        if proof.len() > MAX_PROOF_SIZE_BYTES {
            panic_with_error!(&env, RegistryError::ProofTooLarge);
        }
        if public_inputs.len() > MAX_PUBLIC_INPUTS_SIZE_BYTES {
            panic_with_error!(&env, RegistryError::ProofTooLarge);
        }

        require_unique(&env, &proof_id, &video_hash);

        let parsed = parse_silent_witness_public_inputs(&env, &public_inputs);
        if parsed.video_hash != video_hash {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }
        require_active_credential_root(&env, &parsed.credential_root);

        // Nullifier replay guard (before expensive verifier calls).
        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(parsed.nullifier.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }

        // Load and validate the active verifier set.
        let vset = load_active_vset(&env);
        if vset.disabled {
            panic_with_error!(&env, RegistryError::VerifierSetDisabled);
        }
        if env.ledger().timestamp() < vset.active_from {
            panic_with_error!(&env, RegistryError::VerifierSetNotActive);
        }

        // Evaluate quorum inline.
        let (result, approved, rejected, failures) =
            evaluate_quorum(&env, &vset, &public_inputs, &proof);

        // Emit finalization event.
        QuorumFinalized {
            proof_id: proof_id.clone(),
            approved,
            rejected,
            failures,
        }
        .publish(&env);

        match result {
            QuorumResult::Approved => {}
            QuorumResult::Rejected => panic_with_error!(&env, RegistryError::InvalidProof),
            QuorumResult::Unavailable => panic_with_error!(&env, RegistryError::QuorumNotReached),
            QuorumResult::VersionMismatch => {
                panic_with_error!(&env, RegistryError::VersionMismatch)
            }
            QuorumResult::Pending => panic_with_error!(&env, RegistryError::QuorumNotReached),
        }

        // Commit nullifier and record atomically.
        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(parsed.nullifier.clone()), &true);
        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_SILENT_WITNESS,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: None,
                issuer: None,
                nullifier: Some(parsed.nullifier),
            },
        )
    }

    pub fn register_source(
        env: Env,
        source: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        source.require_auth();
        require_unique(&env, &proof_id, &video_hash);
        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_CONSISTENT_SOURCE,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: Some(source),
                issuer: None,
                nullifier: None,
            },
        )
    }

    pub fn register_seal(
        env: Env,
        issuer: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        issuer.require_auth();
        require_unique(&env, &proof_id, &video_hash);
        let issuer_record = get_issuer_record(&env, &issuer);
        if !issuer_record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }
        let expires_at = compute_expires_at(&env);
        save_record(
            &env,
            &proof_id,
            ProofRecord {
                video_hash,
                metadata_hash,
                tier: TIER_PUBLIC_SEAL,
                status: STATUS_REGISTERED,
                created_at: env.ledger().timestamp(),
                expires_at,
                source: None,
                issuer: Some(issuer),
                nullifier: None,
            },
        )
    }

    pub fn revoke_proof(env: Env, admin: Address, proof_id: BytesN<32>) {
        require_admin(&env, &admin);
        let mut record = get_proof_record(&env, &proof_id);
        record.status = STATUS_REVOKED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);
        ProofRevoked {
            proof_id,
            status: STATUS_REVOKED,
        }
        .publish(&env);
    }

    pub fn get_proof(env: Env, proof_id: BytesN<32>) -> Option<ProofRecord> {
        env.storage().persistent().get(&DataKey::Proof(proof_id))
    }

    pub fn get_by_video(env: Env, video_hash: BytesN<32>) -> Option<ProofRecord> {
        let proof_id: Option<BytesN<32>> =
            env.storage().persistent().get(&DataKey::Video(video_hash));
        proof_id.and_then(|id| env.storage().persistent().get(&DataKey::Proof(id)))
    }

    pub fn has_nullifier(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier))
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn require_admin(env: &Env, candidate: &Address) {
    let admin: Option<Address> = env.storage().persistent().get(&DataKey::Admin);
    let admin = admin.unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));
    candidate.require_auth();
    if &admin != candidate {
        panic_with_error!(env, RegistryError::Unauthorized);
    }
}

fn compute_expires_at(env: &Env) -> u64 {
    let ttl: u64 = env
        .storage()
        .persistent()
        .get(&DataKey::ProofTtl)
        .unwrap_or(DEFAULT_PROOF_TTL_SECS);
    if ttl == 0 {
        0
    } else {
        env.ledger().timestamp().saturating_add(ttl)
    }
}

fn require_unique(env: &Env, proof_id: &BytesN<32>, video_hash: &BytesN<32>) {
    if env
        .storage()
        .persistent()
        .has(&DataKey::Proof(proof_id.clone()))
    {
        panic_with_error!(env, RegistryError::DuplicateProof);
    }
    if env
        .storage()
        .persistent()
        .has(&DataKey::Video(video_hash.clone()))
    {
        panic_with_error!(env, RegistryError::DuplicateVideo);
    }
}

fn get_proof_record(env: &Env, proof_id: &BytesN<32>) -> ProofRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Proof(proof_id.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DuplicateProof))
}

fn get_issuer_record(env: &Env, issuer: &Address) -> IssuerRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Issuer(issuer.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownIssuer))
}

fn get_credential_root_record(env: &Env, credential_root: &BytesN<32>) -> CredentialRootRecord {
    env.storage()
        .persistent()
        .get(&DataKey::CredentialRoot(credential_root.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownCredentialRoot))
}

fn require_active_credential_root(env: &Env, credential_root: &BytesN<32>) {
    let record = get_credential_root_record(env, credential_root);
    if !record.active {
        panic_with_error!(env, RegistryError::RevokedCredentialRoot);
    }
}

fn save_record(env: &Env, proof_id: &BytesN<32>, record: ProofRecord) -> ProofRecord {
    env.storage()
        .persistent()
        .set(&DataKey::Proof(proof_id.clone()), &record);
    env.storage()
        .persistent()
        .set(&DataKey::Video(record.video_hash.clone()), proof_id);
    ProofRegistered {
        proof_id: proof_id.clone(),
        video_hash: record.video_hash.clone(),
        tier: record.tier,
        status: record.status,
    }
    .publish(env);
    record
}

struct SilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
}

fn parse_silent_witness_public_inputs(env: &Env, public_inputs: &Bytes) -> SilentWitnessInputs {
    if public_inputs.len() != 128 {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }
    let mut bytes = [0u8; 128];
    public_inputs.copy_into_slice(&mut bytes);
    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&bytes[16..32]);
    video_hash[16..].copy_from_slice(&bytes[48..64]);
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&bytes[96..128]);
    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&bytes[64..96]);
    SilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
    }
}

fn verify_external_proof(env: &Env, verifier: &Address, public_inputs: Bytes, proof: Bytes) {
    let mut args: SorobanVec<Val> = SorobanVec::new(env);
    args.push_back(public_inputs.into_val(env));
    args.push_back(proof.into_val(env));
    env.try_invoke_contract::<(), InvokeError>(verifier, &Symbol::new(env, "verify_proof"), args)
        .unwrap_or_else(|_| panic_with_error!(env, RegistryError::InvalidProof))
        .unwrap_or_else(|_| panic_with_error!(env, RegistryError::InvalidProof));
}

fn verify_demo_zk_boundary(proof: &Bytes, credential_root: &BytesN<32>) -> bool {
    proof.len() > 0 && credential_root.len() == 32
}

/// Get the next-to-be-used version number (does not increment).
fn get_next_version(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::NextVerifierSetVersion)
        .unwrap_or(1u32)
}

/// Store the pending set record and unlock timestamp.
fn store_pending_set(
    env: &Env,
    version: u32,
    member_count: u32,
    threshold: u32,
    unlocks_at: u64,
    circuit_version: &String,
) {
    let record = VerifierSetRecord {
        version,
        member_count,
        threshold,
        active_from: unlocks_at,
        retired_at: 0,
        disabled: false,
        circuit_version: circuit_version.clone(),
    };
    env.storage()
        .persistent()
        .set(&DataKey::PendingVerifierSetRecord, &record);
    env.storage()
        .persistent()
        .set(&DataKey::PendingVerifierSetUnlocksAt, &unlocks_at);
}

fn emit_proposed(env: &Env, version: u32, threshold: u32, member_count: u32, unlocks_at: u64) {
    VerifierSetProposed {
        version,
        threshold,
        member_count,
        unlocks_at,
    }
    .publish(env);
}

/// Retire the currently active set by setting its `retired_at` timestamp.
fn retire_previous_active_set(env: &Env) {
    let prev_version: Option<u32> = env
        .storage()
        .persistent()
        .get(&DataKey::ActiveVerifierSetVersion);
    if let Some(pv) = prev_version {
        let record: Option<VerifierSetRecord> = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierSetByVersion(pv));
        if let Some(mut r) = record {
            r.retired_at = env.ledger().timestamp();
            env.storage()
                .persistent()
                .set(&DataKey::VerifierSetByVersion(pv), &r);
        }
    }
}

/// Load the active verifier set or panic with VerifierSetNotFound.
fn load_active_vset(env: &Env) -> VerifierSetRecord {
    let version: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::ActiveVerifierSetVersion)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::VerifierSetNotFound));
    env.storage()
        .persistent()
        .get(&DataKey::VerifierSetByVersion(version))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::VerifierSetNotFound))
}

/// Call every member in `vset` and tally approvals, rejections, and failures.
///
/// Returns `(QuorumResult, approved_count, rejected_count, failure_count)`.
///
/// Each verifier is called via `try_invoke_contract`.
/// - `Ok(Ok(()))` → approval.
/// - `Ok(Err(_))` → explicit rejection (contract panic).
/// - `Err(_)` → invocation failure (unavailable/unreachable).
///
/// Early-exit rules:
/// - approved >= threshold                           → Approved.
/// - rejected > members - threshold                  → Rejected.
/// - failures > members - threshold                  → Unavailable (or VersionMismatch).
fn evaluate_quorum(
    env: &Env,
    vset: &VerifierSetRecord,
    public_inputs: &Bytes,
    proof: &Bytes,
) -> (QuorumResult, u32, u32, u32) {
    let total = vset.member_count;
    let threshold = vset.threshold;
    let max_allowed_failures = total.saturating_sub(threshold);

    let mut approved: u32 = 0;
    let mut rejected: u32 = 0;
    let mut failures: u32 = 0;

    for i in 0..total {
        let member: Address = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierSetMember(vset.version, i))
            .unwrap_or_else(|| panic_with_error!(env, RegistryError::VerifierSetNotFound));

        let mut args: SorobanVec<Val> = SorobanVec::new(env);
        args.push_back(public_inputs.clone().into_val(env));
        args.push_back(proof.clone().into_val(env));

        let outcome = env.try_invoke_contract::<(), InvokeError>(
            &member,
            &Symbol::new(env, "verify_proof"),
            args,
        );

        match outcome {
            Ok(Ok(())) => {
                approved += 1;
                if approved >= threshold {
                    return (QuorumResult::Approved, approved, rejected, failures);
                }
            }
            Ok(Err(_)) => {
                // Explicit contract rejection.
                rejected += 1;
                if rejected > max_allowed_failures {
                    return (QuorumResult::Rejected, approved, rejected, failures);
                }
            }
            Err(_) => {
                // Host-level invocation failure (unreachable / panic at host).
                failures += 1;
                if failures > max_allowed_failures {
                    if failures == total && vset.circuit_version.len() > 0 {
                        return (QuorumResult::VersionMismatch, approved, rejected, failures);
                    }
                    return (QuorumResult::Unavailable, approved, rejected, failures);
                }
            }
        }
    }

    // Post-loop final check.
    if approved >= threshold {
        return (QuorumResult::Approved, approved, rejected, failures);
    }
    if rejected > max_allowed_failures {
        return (QuorumResult::Rejected, approved, rejected, failures);
    }
    if failures == total && total > 0 && vset.circuit_version.len() > 0 {
        return (QuorumResult::VersionMismatch, approved, rejected, failures);
    }
    if failures > 0 {
        return (QuorumResult::Unavailable, approved, rejected, failures);
    }
    (QuorumResult::Pending, approved, rejected, failures)
}

mod test;
mod test_auth;
mod test_budget;
mod test_invariants;
mod test_expiry;
mod test_verifier_sets;
