//! Canonical verifier-input codec for Harpocrates (codec `hpx-vi/1`).
//!
//! Soroban/Rust side of a three-way codec that must agree byte for byte with:
//!
//! - `backend/verifier_inputs.py` (Python)
//! - `frontend/src/verifierInputs.ts` (browser / TypeScript)
//!
//! Agreement is enforced by the shared corpus in
//! `zk/vectors/verifier_conformance_v1.json`; see
//! `docs/zk-conformance-vectors.md`.
//!
//! The module is deliberately `no_std`, allocation-free, and independent of the
//! Soroban SDK: it operates on fixed-size byte slices so the same code can be
//! exercised by host-side tests and by the contract itself. All work is O(1) in
//! the size of a frame, so a hostile caller cannot drive cost through it.

/// Codec identifier carried in signals and documentation.
pub const CODEC_ID: &str = "hpx-vi/1";

pub const FIELD_LEN: usize = 32;
pub const SILENT_WITNESS_FIELD_COUNT: usize = 5;
pub const REVOCATION_FIELD_COUNT: usize = 4;
pub const PUBLIC_INPUTS_LEN: usize = FIELD_LEN * SILENT_WITNESS_FIELD_COUNT; // 160
pub const SILENT_WITNESS_PUBLIC_INPUTS_LEN: usize = 160;
pub const REVOCATION_PUBLIC_INPUTS_LEN: usize = 128;

/// Accepted proof-blob size window. Matches the Python and TypeScript layers.
pub const MIN_PROOF_BYTES: u32 = 64;
pub const MAX_PROOF_BYTES: u32 = 65_536;

/// BN254 scalar field modulus, big-endian. A 32-byte encoding is canonical only
/// when the value it denotes is strictly below this.
pub const BN254_SCALAR_FIELD_MODULUS_BE: [u8; FIELD_LEN] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Expected Silent Witness domain tag SHA-256 digest.
pub const SILENT_WITNESS_DOMAIN_TAG_BE: [u8; FIELD_LEN] = [
    0x4a, 0xa0, 0x38, 0xf0, 0xa2, 0x7b, 0x66, 0x75, 0xd7, 0x12, 0x2a, 0xe2, 0xd4, 0xe1, 0x97, 0xc2,
    0x1e, 0x83, 0xfb, 0xe3, 0x01, 0x43, 0xa5, 0xc8, 0x3f, 0xf3, 0x5c, 0x95, 0x14, 0xb9, 0x2c, 0x55,
];

/// Stable rejection codes shared across circuit, backend, browser, and chain.
///
/// The string form is the wire identity used by the conformance corpus; the
/// discriminants are stable and may only be appended to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectCode {
    MalformedHex,
    Length,
    Padding,
    NonCanonicalField,
    ZeroField,
    DomainMismatch,
    ProofUndersize,
    ProofOversize,
    UnknownSchema,
}

/// Numeric result meaning "the material was accepted", returned by the
/// on-chain `classify_public_inputs` entry point.
pub const ACCEPTED_CODE: u32 = 0;

impl RejectCode {
    /// Stable numeric identity, used where a `&'static str` cannot cross the
    /// Soroban host boundary. Values are append-only.
    pub const fn as_code(self) -> u32 {
        match self {
            RejectCode::MalformedHex => 1,
            RejectCode::Length => 2,
            RejectCode::Padding => 3,
            RejectCode::NonCanonicalField => 4,
            RejectCode::ZeroField => 5,
            RejectCode::DomainMismatch => 6,
            RejectCode::ProofUndersize => 7,
            RejectCode::ProofOversize => 8,
            RejectCode::UnknownSchema => 9,
        }
    }

    /// Resolve a wire identity from the conformance corpus. Returns `None` for
    /// unrecognised codes so an out-of-date runner fails loudly.
    pub fn from_wire(value: &str) -> Option<RejectCode> {
        match value {
            "malformed_hex" => Some(RejectCode::MalformedHex),
            "length" => Some(RejectCode::Length),
            "padding" => Some(RejectCode::Padding),
            "non_canonical_field" => Some(RejectCode::NonCanonicalField),
            "zero_field" => Some(RejectCode::ZeroField),
            "domain_mismatch" => Some(RejectCode::DomainMismatch),
            "proof_undersize" => Some(RejectCode::ProofUndersize),
            "proof_oversize" => Some(RejectCode::ProofOversize),
            "unknown_schema" => Some(RejectCode::UnknownSchema),
            _ => None,
        }
    }

    /// Wire identity of this code, as it appears in the conformance corpus.
    pub const fn as_str(self) -> &'static str {
        match self {
            RejectCode::MalformedHex => "malformed_hex",
            RejectCode::Length => "length",
            RejectCode::Padding => "padding",
            RejectCode::NonCanonicalField => "non_canonical_field",
            RejectCode::ZeroField => "zero_field",
            RejectCode::DomainMismatch => "domain_mismatch",
            RejectCode::ProofUndersize => "proof_undersize",
            RejectCode::ProofOversize => "proof_oversize",
            RejectCode::UnknownSchema => "unknown_schema",
        }
    }
}

pub const SCHEMA_SILENT_WITNESS: &str = "silent_witness/v1";
pub const SCHEMA_REVOCATION_WITNESS: &str = "revocation_witness/v1";

/// Parsed `silent_witness/v1` public inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SilentWitnessFields {
    pub video_hash: [u8; FIELD_LEN],
    pub credential_root: [u8; FIELD_LEN],
    pub nullifier: [u8; FIELD_LEN],
    pub domain_tag: [u8; FIELD_LEN],
}

/// Parsed `revocation_witness/v1` public inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationFields {
    pub revocation_root: [u8; FIELD_LEN],
    pub nullifier: [u8; FIELD_LEN],
    pub domain_separator: [u8; FIELD_LEN],
    pub credential_root: [u8; FIELD_LEN],
}

#[inline]
fn field_at(frame: &[u8], index: usize) -> [u8; FIELD_LEN] {
    let mut out = [0u8; FIELD_LEN];
    out.copy_from_slice(&frame[index * FIELD_LEN..(index + 1) * FIELD_LEN]);
    out
}

/// Is this 32-byte big-endian encoding strictly below the BN254 modulus?
pub fn is_canonical_field(element: &[u8; FIELD_LEN]) -> bool {
    for index in 0..FIELD_LEN {
        if element[index] < BN254_SCALAR_FIELD_MODULUS_BE[index] {
            return true;
        }
        if element[index] > BN254_SCALAR_FIELD_MODULUS_BE[index] {
            return false;
        }
    }
    // Exactly equal to the modulus is not a canonical encoding.
    false
}

fn is_zero(element: &[u8; FIELD_LEN]) -> bool {
    let mut acc = 0u8;
    for byte in element.iter() {
        acc |= *byte;
    }
    acc == 0
}

/// A 128-bit half is carried in the low 16 bytes; the high 16 must be zero.
fn has_half_padding(element: &[u8; FIELD_LEN]) -> bool {
    let mut acc = 0u8;
    for byte in element.iter().take(16) {
        acc |= *byte;
    }
    acc == 0
}

/// Enforce the accepted proof-blob size window.
pub fn check_proof_bounds(proof_len: u32) -> Result<(), RejectCode> {
    if proof_len < MIN_PROOF_BYTES {
        return Err(RejectCode::ProofUndersize);
    }
    if proof_len > MAX_PROOF_BYTES {
        return Err(RejectCode::ProofOversize);
    }
    Ok(())
}

/// Parse `silent_witness/v1` public inputs in canonical check order.
pub fn parse_silent_witness(
    frame: &[u8],
    expected_domain: &[u8; FIELD_LEN],
) -> Result<SilentWitnessFields, RejectCode> {
    if frame.len() != SILENT_WITNESS_PUBLIC_INPUTS_LEN {
        return Err(RejectCode::Length);
    }

    let fields = [
        field_at(frame, 0),
        field_at(frame, 1),
        field_at(frame, 2),
        field_at(frame, 3),
        field_at(frame, 4),
    ];

    if !has_half_padding(&fields[0]) || !has_half_padding(&fields[1]) {
        return Err(RejectCode::Padding);
    }

    for element in fields.iter() {
        if !is_canonical_field(element) {
            return Err(RejectCode::NonCanonicalField);
        }
    }

    if is_zero(&fields[2]) || is_zero(&fields[3]) || is_zero(&fields[4]) {
        return Err(RejectCode::ZeroField);
    }

    if &fields[4] != expected_domain {
        return Err(RejectCode::DomainMismatch);
    }

    let mut video_hash = [0u8; FIELD_LEN];
    video_hash[..16].copy_from_slice(&fields[0][16..]);
    video_hash[16..].copy_from_slice(&fields[1][16..]);

    Ok(SilentWitnessFields {
        video_hash,
        credential_root: fields[2],
        nullifier: fields[3],
        domain_tag: fields[4],
    })
}

/// Parse `revocation_witness/v1` public inputs in canonical check order.
///
/// `expected_domain` is supplied by the caller so the contract's single
/// `REVOCATION_DOMAIN_SEPARATOR` constant remains the one authority for the
/// domain value.
pub fn parse_revocation_witness(
    frame: &[u8],
    expected_domain: &[u8; FIELD_LEN],
) -> Result<RevocationFields, RejectCode> {
    if frame.len() != REVOCATION_PUBLIC_INPUTS_LEN {
        return Err(RejectCode::Length);
    }

    let fields = [
        field_at(frame, 0),
        field_at(frame, 1),
        field_at(frame, 2),
        field_at(frame, 3),
    ];

    for element in fields.iter() {
        if !is_canonical_field(element) {
            return Err(RejectCode::NonCanonicalField);
        }
    }

    if is_zero(&fields[0]) || is_zero(&fields[1]) || is_zero(&fields[3]) {
        return Err(RejectCode::ZeroField);
    }

    if &fields[2] != expected_domain {
        return Err(RejectCode::DomainMismatch);
    }

    Ok(RevocationFields {
        revocation_root: fields[0],
        nullifier: fields[1],
        domain_separator: fields[2],
        credential_root: fields[3],
    })
}

/// Classify one conformance case from already-decoded bytes.
///
/// Returns `Ok(())` when the material is accepted. The check order — public
/// inputs first, then the proof blob — is part of the codec contract and is
/// mirrored by every layer.
pub fn classify(
    schema: &str,
    public_inputs: &[u8],
    proof_len: u32,
    expected_domain: &[u8; FIELD_LEN],
) -> Result<(), RejectCode> {
    // Schema dispatch precedes the length check, matching the Python and
    // TypeScript layers: an unrecognised schema is reported as such even when
    // the frame is also the wrong length.
    if schema != SCHEMA_SILENT_WITNESS && schema != SCHEMA_REVOCATION_WITNESS {
        return Err(RejectCode::UnknownSchema);
    }

    if schema == SCHEMA_SILENT_WITNESS {
        parse_silent_witness(public_inputs, expected_domain)?;
    } else {
        parse_revocation_witness(public_inputs, expected_domain)?;
    }

    check_proof_bounds(proof_len)
}

