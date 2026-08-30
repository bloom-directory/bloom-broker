//! System Program native transfer instruction.
//!
//! A native SOL transfer invokes the System Program
//! (`11111111111111111111111111111111`) with the `Transfer` variant. Its data
//! is exactly 12 bytes: a little-endian `u32` opcode (`2`) followed by a
//! little-endian `u64` lamport amount.
//!
//! The canonical compiled form of a single-signer transfer is a legacy message
//! whose account keys are `[fee_payer, destination, system_program]`, with one
//! instruction `{ program_id_index: 2, accounts: [0, 1], data: transfer_data }`
//! and header `{ 1, 0, 1 }`.

use thiserror::Error;

use crate::message::{CompiledInstruction, LegacyMessage, MessageHeader};
use crate::pubkey::Pubkey;

/// The System Program public key (`11111111111111111111111111111111`).
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_bytes([0u8; 32]);

/// The `Transfer` variant index of `SystemInstruction`.
pub const TRANSFER_OPCODE: u32 = 2;

/// Exact serialized length of a transfer instruction data payload.
pub const TRANSFER_DATA_LEN: usize = 12;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SystemTransferError {
    #[error("destination equals the source")]
    DestinationIsSource,
    #[error("lamport amount is zero")]
    ZeroLamports,
    #[error("transfer requires exactly two account indices, got {0}")]
    BadAccountCount(usize),
}

/// Encode the 12-byte System Program transfer instruction data for `lamports`.
pub fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(TRANSFER_DATA_LEN);
    data.extend_from_slice(&TRANSFER_OPCODE.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

/// Decode the transfer opcode and lamports from a 12-byte data payload.
///
/// Returns `None` when the payload does not begin with the transfer opcode or
/// is not exactly 12 bytes.
pub fn decode_transfer_data(data: &[u8]) -> Option<u64> {
    if data.len() != TRANSFER_DATA_LEN {
        return None;
    }
    let opcode = u32::from_le_bytes(data[0..4].try_into().ok()?);
    if opcode != TRANSFER_OPCODE {
        return None;
    }
    Some(u64::from_le_bytes(data[4..12].try_into().ok()?))
}

/// The canonical compiled instruction for a native transfer.
pub fn transfer_instruction(lamports: u64) -> Result<CompiledInstruction, SystemTransferError> {
    if lamports == 0 {
        return Err(SystemTransferError::ZeroLamports);
    }
    Ok(CompiledInstruction {
        program_id_index: 2,
        accounts: vec![0, 1],
        data: transfer_data(lamports),
    })
}

/// Build the canonical legacy message for a single-signer native transfer.
///
/// `account_keys = [fee_payer, destination, system_program]`, one transfer
/// instruction, header `{ 1, 0, 1 }`.
pub fn transfer_message(
    fee_payer: Pubkey,
    destination: Pubkey,
    lamports: u64,
    recent_blockhash: [u8; 32],
) -> Result<LegacyMessage, SystemTransferError> {
    if destination == fee_payer {
        return Err(SystemTransferError::DestinationIsSource);
    }
    if lamports == 0 {
        return Err(SystemTransferError::ZeroLamports);
    }
    Ok(LegacyMessage {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        },
        account_keys: vec![fee_payer, destination, SYSTEM_PROGRAM_ID],
        recent_blockhash,
        instructions: vec![CompiledInstruction {
            program_id_index: 2,
            accounts: vec![0, 1],
            data: transfer_data(lamports),
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_data_encoding() {
        assert_eq!(transfer_data(0), [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            transfer_data(1_000_000_000),
            [2, 0, 0, 0, 0x00, 0xca, 0x9a, 0x3b, 0, 0, 0, 0]
        );
        assert_eq!(decode_transfer_data(&transfer_data(42)), Some(42));
    }

    #[test]
    fn decode_rejects_wrong_opcode() {
        let mut data = transfer_data(1);
        data[0] = 3;
        assert_eq!(decode_transfer_data(&data), None);
    }

    #[test]
    fn decode_rejects_wrong_len() {
        assert_eq!(
            decode_transfer_data(&[2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
            None
        );
        let mut data = transfer_data(1);
        data.push(0);
        assert_eq!(decode_transfer_data(&data), None);
    }
}
