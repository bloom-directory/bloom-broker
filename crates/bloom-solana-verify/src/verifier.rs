//! The `solana-system-transfer-v1` semantic verifier.
//!
//! This verifier is network-free and deterministic. It accepts exactly two
//! legacy, single-signer forms — one System Program native transfer, or the
//! same transfer carried on a durable nonce as `[advance-nonce, transfer]` —
//! and establishes the facts listed in the
//! native system-claim contract. Every other shape is
//! rejected with a precise reason.
//!
//! Facts established: complete canonical legacy encoding (no trailing bytes),
//! signed size within the Solana packet limit, exactly one required signer,
//! the selected Ed25519 public key as both fee payer and transfer source,
//! exactly one instruction targeting the System Program, exactly the native
//! transfer opcode with canonical data length, the destination public key, the
//! lamport debit, and the message commitment (SHA-256 digest / ordered signing
//! hash).
//!
//! Facts it does *not* establish: cluster/genesis identity, blockhash
//! freshness, last-valid height, fee quote, balance, simulation result,
//! broadcast acceptance, or finality. Those remain `machine_asserted`.

use crate::message::{self, LegacyMessage};
use crate::message_digest;
use crate::pubkey::Pubkey;
use crate::system_transfer::{
    SYSTEM_PROGRAM_ID, SYSVAR_RECENT_BLOCKHASHES, decode_advance_data, decode_transfer_data,
};
use serde::{Deserialize, Serialize};

/// Solana's maximum transaction packet size (bytes).
pub const PACKET_DATA_SIZE: usize = 1232;

/// Maximum serialized message size once a single-signature (65-byte) signature
/// area is accounted for.
pub const MAX_MESSAGE_SIZE: usize = PACKET_DATA_SIZE - (1 + 64);

/// Why a message was rejected by the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RejectionReason {
    /// Message did not parse as a canonical legacy message.
    Malformed { detail: String },
    /// Signed transaction would exceed the packet limit.
    Oversized { message_len: usize },
    /// More than one required signer (multisigner/partial signing form).
    MultipleSigners { count: u8 },
    /// A signer other than the fee payer was marked read-only (ambiguous role).
    /// The account layout is not exactly [fee_payer, destination, system_program].
    UnexpectedAccountLayout { account_count: usize },
    /// The fee payer is not the selected Ed25519 child public key.
    FeePayerMismatch { expected: String, actual: String },
    /// The fee payer, destination, and system program accounts are not all
    /// distinct (duplicate/overlapping account roles).
    AmbiguousAccountRole,
    /// The system program account is missing from its canonical position.
    MissingSystemProgram,
    /// The message does not contain exactly one instruction.
    UnexpectedInstructionCount { count: usize },
    /// The single instruction does not target the System Program.
    NotSystemProgram { program_id_index: u8 },
    /// The instruction does not reference accounts [0, 1].
    UnexpectedInstructionAccounts,
    /// The instruction data is not the native transfer opcode with canonical length.
    NotNativeTransfer,
    /// A five-account message whose first instruction is not a well-formed
    /// advance-nonce (wrong accounts, length, or opcode).
    NonceAdvanceNotFirst,
    /// The advance-nonce authority is not the fee payer (single-signer
    /// shape broken).
    NonceAuthorityMismatch,
    /// The nonce-form layout is wrong: sysvar missing from its position,
    /// role collision, or readonly counts that fit neither admitted form.
    UnexpectedNonceLayout,
    /// The extracted destination does not match the claimed destination.
    DestinationMismatch { expected: String, actual: String },
    /// The transfer moves no value.
    ZeroLamports,
    /// The extracted lamports do not match the claimed debit.
    LamportsMismatch { expected: u64, actual: u64 },
    /// The computed message digest does not match the claimed digest.
    DigestMismatch,
}

/// The facts established by a successful verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTransfer {
    /// The fee payer and transfer source public key.
    pub fee_payer: String,
    /// The destination public key.
    pub destination: String,
    /// The lamport debit.
    pub lamports: u64,
    /// The program public key (the System Program).
    pub program: String,
    /// Always `1` for a verified single-signer transfer.
    pub signer_count: u8,
    /// SHA-256 of the serialized message — Bloom's payload commitment, not the
    /// Ed25519 signing input.
    pub message_digest: [u8; 32],
    /// Base58 recent blockhash extracted from the canonical message.
    pub recent_blockhash: String,
}

/// Verify that `message_bytes` is a canonical legacy, single-signer native
/// SOL transfer matching `fee_payer`, `destination`, and `lamports`.
///
/// `claimed_digest`, when present, must equal SHA-256 of `message_bytes`.
pub fn verify_native_transfer(
    message_bytes: &[u8],
    fee_payer: Pubkey,
    destination: Pubkey,
    lamports: u64,
    claimed_digest: Option<[u8; 32]>,
) -> Result<VerifiedTransfer, RejectionReason> {
    // Reject oversized input before parsing or allocating anything: the
    // signed transaction must fit the packet limit, so the message itself is
    // bounded regardless of what its short-vec length prefixes claim.
    if message_bytes.len() > MAX_MESSAGE_SIZE {
        return Err(RejectionReason::Oversized {
            message_len: message_bytes.len(),
        });
    }

    let message: LegacyMessage = match message::parse_message(message_bytes) {
        Ok(m) => m,
        Err(e) => {
            return Err(RejectionReason::Malformed {
                detail: e.to_string(),
            });
        }
    };

    // Exactly one required signer.
    if message.header.num_required_signatures != 1 {
        return Err(RejectionReason::MultipleSigners {
            count: message.header.num_required_signatures,
        });
    }
    // Dispatch on the two admitted layouts before any shape-specific gate,
    // so the nonce form never falls into the legacy refusals below.
    if message.account_keys.len() == 5 && message.header.num_readonly_unsigned_accounts == 2 {
        return verify_nonce_transfer(
            &message,
            message_bytes,
            fee_payer,
            destination,
            lamports,
            claimed_digest,
        );
    }
    // Canonical account layout: [fee_payer, destination, system_program].
    if message.account_keys.len() != 3 {
        return Err(RejectionReason::UnexpectedAccountLayout {
            account_count: message.account_keys.len(),
        });
    }
    if message.header.num_readonly_unsigned_accounts != 1 {
        return Err(RejectionReason::UnexpectedAccountLayout {
            account_count: message.account_keys.len(),
        });
    }

    let actual_payer = message.fee_payer();
    if actual_payer != fee_payer {
        return Err(RejectionReason::FeePayerMismatch {
            expected: fee_payer.to_string(),
            actual: actual_payer.to_string(),
        });
    }
    if message.account_keys[2] != SYSTEM_PROGRAM_ID {
        return Err(RejectionReason::MissingSystemProgram);
    }

    // The three account roles must be distinct: a transfer to oneself, a
    // destination or payer equal to the System Program, or any other
    // duplicated account key is an ambiguous role and is rejected.
    let actual_destination = message.account_keys[1];
    if actual_destination == actual_payer
        || actual_destination == SYSTEM_PROGRAM_ID
        || actual_payer == SYSTEM_PROGRAM_ID
    {
        return Err(RejectionReason::AmbiguousAccountRole);
    }

    if message.instructions.len() != 1 {
        return Err(RejectionReason::UnexpectedInstructionCount {
            count: message.instructions.len(),
        });
    }
    let ix = &message.instructions[0];
    if ix.program_id_index != 2 {
        return Err(RejectionReason::NotSystemProgram {
            program_id_index: ix.program_id_index,
        });
    }
    if ix.accounts != [0, 1] {
        return Err(RejectionReason::UnexpectedInstructionAccounts);
    }

    let actual_lamports =
        decode_transfer_data(ix.data.as_slice()).ok_or(RejectionReason::NotNativeTransfer)?;
    // A zero-lamport transfer moves nothing while still consuming an
    // approval, a nonce and a signature over a real message. The constructor
    // already refuses to build one, so accepting it here would mean the
    // verifier admits a shape Bloom itself will not produce.
    if actual_lamports == 0 {
        return Err(RejectionReason::ZeroLamports);
    }
    if actual_lamports != lamports {
        return Err(RejectionReason::LamportsMismatch {
            expected: lamports,
            actual: actual_lamports,
        });
    }

    if actual_destination != destination {
        return Err(RejectionReason::DestinationMismatch {
            expected: destination.to_string(),
            actual: actual_destination.to_string(),
        });
    }

    let digest = message_digest(message_bytes);
    if let Some(claimed) = claimed_digest
        && claimed != digest
    {
        return Err(RejectionReason::DigestMismatch);
    }

    Ok(VerifiedTransfer {
        fee_payer: actual_payer.to_string(),
        destination: actual_destination.to_string(),
        lamports: actual_lamports,
        program: SYSTEM_PROGRAM_ID.to_string(),
        signer_count: 1,
        message_digest: digest,
        recent_blockhash: bs58::encode(message.recent_blockhash).into_string(),
    })
}

/// Verify the one admitted nonce-carried form: account keys
/// `[fee_payer, nonce_account, destination, system_program, sysvar]`,
/// header `{ 1, 0, 2 }`, instructions `[advance-nonce, transfer]`.
///
/// The advance authority must be the fee payer, so exactly one signature is
/// required. The recent blockhash carries the stored nonce value; its
/// freshness is NOT established here (no RPC in the verifier) and stays a
/// Machine-side live check.
fn verify_nonce_transfer(
    message: &LegacyMessage,
    message_bytes: &[u8],
    fee_payer: Pubkey,
    destination: Pubkey,
    lamports: u64,
    claimed_digest: Option<[u8; 32]>,
) -> Result<VerifiedTransfer, RejectionReason> {
    let actual_payer = message.fee_payer();
    if actual_payer != fee_payer {
        return Err(RejectionReason::FeePayerMismatch {
            expected: fee_payer.to_string(),
            actual: actual_payer.to_string(),
        });
    }
    if message.account_keys[3] != SYSTEM_PROGRAM_ID {
        return Err(RejectionReason::MissingSystemProgram);
    }
    if message.account_keys[4] != SYSVAR_RECENT_BLOCKHASHES {
        return Err(RejectionReason::UnexpectedNonceLayout);
    }
    // payer, nonce account, and destination must be three distinct roles,
    // none of them the System Program.
    let actual_nonce = message.account_keys[1];
    let actual_destination = message.account_keys[2];
    if actual_nonce == actual_payer
        || actual_destination == actual_payer
        || actual_nonce == actual_destination
        || actual_nonce == SYSTEM_PROGRAM_ID
        || actual_destination == SYSTEM_PROGRAM_ID
        || actual_payer == SYSTEM_PROGRAM_ID
    {
        return Err(RejectionReason::AmbiguousAccountRole);
    }

    if message.instructions.len() != 2 {
        return Err(RejectionReason::UnexpectedInstructionCount {
            count: message.instructions.len(),
        });
    }
    let advance = &message.instructions[0];
    if advance.program_id_index != 3 {
        return Err(RejectionReason::NotSystemProgram {
            program_id_index: advance.program_id_index,
        });
    }
    if decode_advance_data(advance.data.as_slice()).is_none() {
        return Err(RejectionReason::NonceAdvanceNotFirst);
    }
    if advance.accounts.len() != 3 {
        return Err(RejectionReason::UnexpectedInstructionAccounts);
    }
    if advance.accounts[0] != 1 || advance.accounts[1] != 4 {
        return Err(RejectionReason::NonceAdvanceNotFirst);
    }
    if advance.accounts[2] != 0 {
        return Err(RejectionReason::NonceAuthorityMismatch);
    }

    let ix = &message.instructions[1];
    if ix.program_id_index != 3 {
        return Err(RejectionReason::NotSystemProgram {
            program_id_index: ix.program_id_index,
        });
    }
    if ix.accounts != [0, 2] {
        return Err(RejectionReason::UnexpectedInstructionAccounts);
    }
    let actual_lamports =
        decode_transfer_data(ix.data.as_slice()).ok_or(RejectionReason::NotNativeTransfer)?;
    if actual_lamports == 0 {
        return Err(RejectionReason::ZeroLamports);
    }
    if actual_lamports != lamports {
        return Err(RejectionReason::LamportsMismatch {
            expected: lamports,
            actual: actual_lamports,
        });
    }
    if actual_destination != destination {
        return Err(RejectionReason::DestinationMismatch {
            expected: destination.to_string(),
            actual: actual_destination.to_string(),
        });
    }

    let digest = message_digest(message_bytes);
    if let Some(claimed) = claimed_digest
        && claimed != digest
    {
        return Err(RejectionReason::DigestMismatch);
    }

    Ok(VerifiedTransfer {
        fee_payer: actual_payer.to_string(),
        destination: actual_destination.to_string(),
        lamports: actual_lamports,
        program: SYSTEM_PROGRAM_ID.to_string(),
        signer_count: 1,
        message_digest: digest,
        recent_blockhash: bs58::encode(message.recent_blockhash).into_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_transfer::{nonce_transfer_message, transfer_message};

    /// Live reference parties: payer `5N2d…qqP`, nonce `L8FA…Ji6`,
    /// destination `GVD…PDhHn`, nonce value `2ckP…E11JE7` — built by
    /// `solana transfer --nonce` and settled on a local validator.
    fn reference_nonce() -> (Pubkey, Pubkey, Pubkey, [u8; 32]) {
        (
            Pubkey::from_bytes([
                0x40, 0xd1, 0xca, 0x05, 0xdc, 0xc0, 0x51, 0x40, 0xe0, 0x5c, 0x74, 0x81, 0x3c, 0x69,
                0x22, 0x74, 0xbe, 0x7a, 0x7c, 0x09, 0x39, 0x0b, 0x80, 0xca, 0x83, 0x09, 0x90, 0xd1,
                0xc3, 0x5f, 0x6c, 0x1e,
            ]),
            Pubkey::from_bytes([
                0x04, 0xe6, 0x39, 0xec, 0x5c, 0xcd, 0x14, 0x9c, 0xfa, 0xed, 0xa5, 0x8d, 0x7e, 0x65,
                0x51, 0x49, 0xf1, 0x4a, 0xcd, 0xa4, 0xce, 0xd1, 0x77, 0xf9, 0xa1, 0xd0, 0x00, 0x24,
                0xe7, 0x1a, 0x33, 0xc3,
            ]),
            Pubkey::from_bytes([
                0xe6, 0x19, 0x5a, 0x90, 0xbf, 0xa1, 0x71, 0xda, 0x89, 0xb9, 0x47, 0x56, 0x6e, 0x9f,
                0x66, 0x7a, 0xc5, 0xd0, 0x92, 0xcd, 0x03, 0xc9, 0x8e, 0xfd, 0xf4, 0x04, 0xb4, 0xd6,
                0x96, 0xd2, 0x9d, 0xed,
            ]),
            [
                0x18, 0x04, 0x12, 0xcf, 0x07, 0xcb, 0x03, 0xa4, 0x03, 0xb3, 0x4e, 0x1b, 0x74, 0x2b,
                0x8b, 0x9d, 0x77, 0x93, 0x38, 0xce, 0xdc, 0x2b, 0x1c, 0x19, 0x10, 0xdc, 0xd1, 0xdd,
                0x2d, 0xfb, 0x2d, 0xbc,
            ],
        )
    }

    #[test]
    fn accepts_nonce_reference_vector() {
        let (payer, nonce, dest, value) = reference_nonce();
        let bytes = nonce_transfer_message(payer, nonce, dest, 1_000_000, value)
            .unwrap()
            .serialize();
        assert_eq!(bytes.len(), 224);
        let digest = message_digest(&bytes);
        let verified =
            verify_native_transfer(&bytes, payer, dest, 1_000_000, Some(digest)).unwrap();
        assert_eq!(verified.fee_payer, payer.to_string());
        assert_eq!(verified.destination, dest.to_string());
        assert_eq!(verified.lamports, 1_000_000);
        assert_eq!(
            verified.recent_blockhash,
            "2ckPU2gn7kU5Pb5wWLNtbbPSxXeJZCQWg23UbrE11JE7"
        );
    }

    #[test]
    fn rejects_swapped_instruction_order() {
        let (payer, nonce, dest, value) = reference_nonce();
        let mut msg = nonce_transfer_message(payer, nonce, dest, 1, value).unwrap();
        msg.instructions.swap(0, 1);
        assert_eq!(
            verify_native_transfer(&msg.serialize(), payer, dest, 1, None).unwrap_err(),
            RejectionReason::NonceAdvanceNotFirst
        );
    }

    #[test]
    fn rejects_foreign_advance_authority() {
        let (payer, nonce, dest, value) = reference_nonce();
        let mut msg = nonce_transfer_message(payer, nonce, dest, 1, value).unwrap();
        msg.instructions[0].accounts = vec![1, 4, 2];
        assert_eq!(
            verify_native_transfer(&msg.serialize(), payer, dest, 1, None).unwrap_err(),
            RejectionReason::NonceAuthorityMismatch
        );
    }

    #[test]
    fn rejects_third_instruction() {
        let (payer, nonce, dest, value) = reference_nonce();
        let mut msg = nonce_transfer_message(payer, nonce, dest, 1, value).unwrap();
        msg.instructions.push(msg.instructions[1].clone());
        assert_eq!(
            verify_native_transfer(&msg.serialize(), payer, dest, 1, None).unwrap_err(),
            RejectionReason::UnexpectedInstructionCount { count: 3 }
        );
    }

    #[test]
    fn rejects_wrong_sysvar_position() {
        let (payer, nonce, dest, value) = reference_nonce();
        let mut msg = nonce_transfer_message(payer, nonce, dest, 1, value).unwrap();
        msg.account_keys[4] = dest;
        assert_eq!(
            verify_native_transfer(&msg.serialize(), payer, dest, 1, None).unwrap_err(),
            RejectionReason::UnexpectedNonceLayout
        );
    }

    #[test]
    fn rejects_nonce_role_collision() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let other = Pubkey::from_bytes([3u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        // Hand-built: nonce account aliases the payer.
        let mut msg = nonce_transfer_message(payer, other, dest, 1, [9u8; 32]).unwrap();
        msg.account_keys[1] = payer;
        assert_eq!(
            verify_native_transfer(&msg.serialize(), payer, dest, 1, None).unwrap_err(),
            RejectionReason::AmbiguousAccountRole
        );
    }

    #[test]
    fn rejects_nonce_amount_mismatch() {
        let (payer, nonce, dest, value) = reference_nonce();
        let bytes = nonce_transfer_message(payer, nonce, dest, 1_000_000, value)
            .unwrap()
            .serialize();
        assert_eq!(
            verify_native_transfer(&bytes, payer, dest, 2_000_000, None).unwrap_err(),
            RejectionReason::LamportsMismatch {
                expected: 2_000_000,
                actual: 1_000_000
            }
        );
    }

    #[test]
    fn accepts_canonical_transfer() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let lamports = 1_000_000_000u64;
        let msg = transfer_message(payer, dest, lamports, [7u8; 32]).unwrap();
        let bytes = msg.serialize();
        let digest = message_digest(&bytes);
        let verified = verify_native_transfer(&bytes, payer, dest, lamports, Some(digest)).unwrap();
        assert_eq!(verified.fee_payer, payer.to_string());
        assert_eq!(verified.destination, dest.to_string());
        assert_eq!(verified.lamports, lamports);
        assert_eq!(verified.program, SYSTEM_PROGRAM_ID.to_string());
        assert_eq!(verified.signer_count, 1);
    }

    #[test]
    fn rejects_multiple_signers() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let mut msg = transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        msg.header.num_required_signatures = 2;
        let bytes = msg.serialize();
        assert_eq!(
            verify_native_transfer(&bytes, payer, dest, 1, None).unwrap_err(),
            RejectionReason::MultipleSigners { count: 2 }
        );
    }

    #[test]
    fn rejects_extra_instruction() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let mut msg = transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        msg.instructions.push(msg.instructions[0].clone());
        let bytes = msg.serialize();
        assert_eq!(
            verify_native_transfer(&bytes, payer, dest, 1, None).unwrap_err(),
            RejectionReason::UnexpectedInstructionCount { count: 2 }
        );
    }

    #[test]
    fn rejects_destination_mismatch() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let msg = transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        let bytes = msg.serialize();
        let other = Pubkey::from_bytes([9u8; 32]);
        assert!(matches!(
            verify_native_transfer(&bytes, payer, other, 1, None).unwrap_err(),
            RejectionReason::DestinationMismatch { .. }
        ));
    }

    #[test]
    fn rejects_lamports_mismatch() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let msg = transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        let bytes = msg.serialize();
        assert_eq!(
            verify_native_transfer(&bytes, payer, dest, 2, None).unwrap_err(),
            RejectionReason::LamportsMismatch {
                expected: 2,
                actual: 1
            }
        );
    }

    #[test]
    fn rejects_fee_payer_mismatch() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let msg = transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        let bytes = msg.serialize();
        let other = Pubkey::from_bytes([8u8; 32]);
        assert!(matches!(
            verify_native_transfer(&bytes, other, dest, 1, None).unwrap_err(),
            RejectionReason::FeePayerMismatch { .. }
        ));
    }

    #[test]
    fn rejects_versioned_message() {
        // A legacy transfer message whose first byte is rewritten to 0x80.
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let msg = transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        let mut bytes = msg.serialize();
        bytes[0] = 0x80;
        assert!(matches!(
            verify_native_transfer(&bytes, payer, dest, 1, None).unwrap_err(),
            RejectionReason::Malformed { .. }
        ));
    }

    #[test]
    fn rejects_self_transfer_as_ambiguous_role() {
        // Destination == fee payer is a duplicate/ambiguous role. The
        // construction helper rejects this outright, so build the message with
        // a distinct destination and rewrite the destination account key.
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let mut msg = transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        msg.account_keys[1] = payer;
        let bytes = msg.serialize();
        assert!(matches!(
            verify_native_transfer(&bytes, payer, payer, 1, None).unwrap_err(),
            RejectionReason::AmbiguousAccountRole
        ));
    }

    #[test]
    fn rejects_destination_equal_to_system_program() {
        // Destination == System Program is a duplicate/ambiguous role.
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = SYSTEM_PROGRAM_ID;
        let msg = transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        let bytes = msg.serialize();
        assert!(matches!(
            verify_native_transfer(&bytes, payer, dest, 1, None).unwrap_err(),
            RejectionReason::AmbiguousAccountRole
        ));
    }

    /// A zero-lamport transfer moves nothing while still consuming an
    /// approval, a nonce, and a signature over a real message. The
    /// constructor refuses to build one, so the verifier must not admit a
    /// shape Bloom itself will not produce.
    #[test]
    fn zero_lamport_transfers_are_refused() {
        // Built by hand precisely because `transfer_message` rejects zero.
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let message = crate::system_transfer::transfer_message(payer, dest, 1, [7u8; 32]).unwrap();
        let mut bytes = message.serialize();
        // Overwrite the little-endian u64 amount in the instruction data with
        // zero, leaving every other byte of a valid message intact.
        let len = bytes.len();
        bytes[len - 8..].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(
            verify_native_transfer(&bytes, payer, dest, 0, None),
            Err(RejectionReason::ZeroLamports)
        ));
    }
}
