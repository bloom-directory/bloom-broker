//! The `solana-system-transfer-v1` semantic verifier.
//!
//! This verifier is network-free and deterministic. It accepts only a legacy,
//! single-signer message containing exactly one System Program native
//! transfer, and establishes the facts listed in the
//! `Verified Chain Petals` architecture contract. Every other shape is
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

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::message::{self, LegacyMessage, ParseError};
use crate::message_digest;
use crate::pubkey::Pubkey;
use crate::system_transfer::{SYSTEM_PROGRAM_ID, decode_transfer_data};

/// Solana's maximum transaction packet size (bytes).
pub const PACKET_DATA_SIZE: usize = 1232;

/// Maximum serialized message size once a single-signature (65-byte) signature
/// area is accounted for.
pub const MAX_MESSAGE_SIZE: usize = PACKET_DATA_SIZE - (1 + 64);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifierError {
    #[error("message parse failed: {0}")]
    Parse(#[from] ParseError),
}

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
    ReadonlySigner { count: u8 },
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
    /// The extracted destination does not match the claimed destination.
    DestinationMismatch { expected: String, actual: String },
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
    verify_transfer_inner(
        message_bytes,
        destination,
        lamports,
        claimed_digest,
        Some(fee_payer),
    )
}

/// Verify that `message_bytes` is a canonical legacy, single-signer native
/// SOL transfer matching `destination` and `lamports`, without binding a
/// *claimed* fee payer.
///
/// The fee payer is the message's single required signer (index 0); its
/// identity is bound to the derived account by the Ed25519 signature over
/// the raw message in the signing path, not by the claim. This is the entry
/// point the Broker's `solana-system-transfer-v1` assurance verifier uses:
/// the claim carries the economic facts (destination, lamports, digest), and
/// the signature carries who paid/signed.
pub fn verify_transfer(
    message_bytes: &[u8],
    destination: Pubkey,
    lamports: u64,
    claimed_digest: Option<[u8; 32]>,
) -> Result<VerifiedTransfer, RejectionReason> {
    verify_transfer_inner(message_bytes, destination, lamports, claimed_digest, None)
}

fn verify_transfer_inner(
    message_bytes: &[u8],
    destination: Pubkey,
    lamports: u64,
    claimed_digest: Option<[u8; 32]>,
    expected_fee_payer: Option<Pubkey>,
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
    if message.header.num_readonly_signed_accounts != 0 {
        return Err(RejectionReason::ReadonlySigner {
            count: message.header.num_readonly_signed_accounts,
        });
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
    if let Some(expected) = expected_fee_payer
        && actual_payer != expected
    {
        return Err(RejectionReason::FeePayerMismatch {
            expected: expected.to_string(),
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
    if actual_lamports != lamports {
        return Err(RejectionReason::LamportsMismatch {
            expected: lamports,
            actual: actual_lamports,
        });
    }

    let actual_destination = message.account_keys[1];
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
    use crate::system_transfer::transfer_message;

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
}
