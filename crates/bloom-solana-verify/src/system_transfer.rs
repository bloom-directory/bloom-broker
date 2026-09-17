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

/// The `AdvanceNonceAccount` variant index of `SystemInstruction`.
pub const ADVANCE_OPCODE: u32 = 4;

/// Exact serialized length of an advance-nonce instruction data payload.
pub const ADVANCE_DATA_LEN: usize = 4;

/// The RecentBlockhashes sysvar
/// (`SysvarRecentB1ockHashes11111111111111111111`), the second account of
/// every advance-nonce instruction.
pub const SYSVAR_RECENT_BLOCKHASHES: Pubkey = Pubkey::from_bytes([
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e, 0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
    0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3, 0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
]);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SystemTransferError {
    #[error("destination equals the source")]
    DestinationIsSource,
    #[error("nonce account collides with another account role")]
    AmbiguousNonceAccount,
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

/// Decode the advance-nonce opcode from a 4-byte data payload.
///
/// Returns `Some(())` only when the payload is exactly the advance opcode
/// with no trailing bytes.
pub fn decode_advance_data(data: &[u8]) -> Option<()> {
    if data.len() != ADVANCE_DATA_LEN {
        return None;
    }
    let opcode = u32::from_le_bytes(data[0..4].try_into().ok()?);
    if opcode != ADVANCE_OPCODE {
        return None;
    }
    Some(())
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

/// Build the canonical nonce-carried message for a single-signer transfer.
///
/// `account_keys = [fee_payer, nonce_account, destination, system_program,
/// sysvar]`, instructions `[advance-nonce, transfer]`, header `{ 1, 0, 2 }`.
/// The authority is the fee payer, so exactly one signature is required.
/// `recent_blockhash` carries the stored nonce value.
pub fn nonce_transfer_message(
    fee_payer: Pubkey,
    nonce_account: Pubkey,
    destination: Pubkey,
    lamports: u64,
    nonce_value: [u8; 32],
) -> Result<LegacyMessage, SystemTransferError> {
    if destination == fee_payer {
        return Err(SystemTransferError::DestinationIsSource);
    }
    if nonce_account == fee_payer || nonce_account == destination {
        return Err(SystemTransferError::AmbiguousNonceAccount);
    }
    if lamports == 0 {
        return Err(SystemTransferError::ZeroLamports);
    }
    Ok(LegacyMessage {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 2,
        },
        account_keys: vec![
            fee_payer,
            nonce_account,
            destination,
            SYSTEM_PROGRAM_ID,
            SYSVAR_RECENT_BLOCKHASHES,
        ],
        recent_blockhash: nonce_value,
        instructions: vec![
            CompiledInstruction {
                program_id_index: 3,
                accounts: vec![1, 4, 0],
                data: ADVANCE_OPCODE.to_le_bytes().to_vec(),
            },
            CompiledInstruction {
                program_id_index: 3,
                accounts: vec![0, 2],
                data: transfer_data(lamports),
            },
        ],
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

    #[test]
    fn sysvar_constant_is_the_recent_blockhashes_sysvar() {
        assert_eq!(
            bs58::encode(SYSVAR_RECENT_BLOCKHASHES.as_bytes()).into_string(),
            "SysvarRecentB1ockHashes11111111111111111111"
        );
    }

    #[test]
    fn decode_advance_accepts_only_canonical_opcode() {
        assert_eq!(decode_advance_data(&[4, 0, 0, 0]), Some(()));
        assert_eq!(decode_advance_data(&[2, 0, 0, 0]), None);
        assert_eq!(decode_advance_data(&[4, 0, 0]), None);
        assert_eq!(decode_advance_data(&[4, 0, 0, 0, 0]), None);
    }

    /// Reference keys from a live `solana transfer --nonce` build
    /// (local validator, settled): payer `5N2d…qqP`, nonce `L8FA…Ji6`,
    /// destination `GVD…PDhHn`, nonce value `2ckP…E11JE7`.
    fn reference_parties() -> (Pubkey, Pubkey, Pubkey, [u8; 32]) {
        let payer = Pubkey::from_bytes([
            0x40, 0xd1, 0xca, 0x05, 0xdc, 0xc0, 0x51, 0x40, 0xe0, 0x5c, 0x74, 0x81, 0x3c, 0x69,
            0x22, 0x74, 0xbe, 0x7a, 0x7c, 0x09, 0x39, 0x0b, 0x80, 0xca, 0x83, 0x09, 0x90, 0xd1,
            0xc3, 0x5f, 0x6c, 0x1e,
        ]);
        let nonce = Pubkey::from_bytes([
            0x04, 0xe6, 0x39, 0xec, 0x5c, 0xcd, 0x14, 0x9c, 0xfa, 0xed, 0xa5, 0x8d, 0x7e, 0x65,
            0x51, 0x49, 0xf1, 0x4a, 0xcd, 0xa4, 0xce, 0xd1, 0x77, 0xf9, 0xa1, 0xd0, 0x00, 0x24,
            0xe7, 0x1a, 0x33, 0xc3,
        ]);
        let dest = Pubkey::from_bytes([
            0xe6, 0x19, 0x5a, 0x90, 0xbf, 0xa1, 0x71, 0xda, 0x89, 0xb9, 0x47, 0x56, 0x6e, 0x9f,
            0x66, 0x7a, 0xc5, 0xd0, 0x92, 0xcd, 0x03, 0xc9, 0x8e, 0xfd, 0xf4, 0x04, 0xb4, 0xd6,
            0x96, 0xd2, 0x9d, 0xed,
        ]);
        let value = [
            0x18, 0x04, 0x12, 0xcf, 0x07, 0xcb, 0x03, 0xa4, 0x03, 0xb3, 0x4e, 0x1b, 0x74, 0x2b,
            0x8b, 0x9d, 0x77, 0x93, 0x38, 0xce, 0xdc, 0x2b, 0x1c, 0x19, 0x10, 0xdc, 0xd1, 0xdd,
            0x2d, 0xfb, 0x2d, 0xbc,
        ];
        (payer, nonce, dest, value)
    }

    #[test]
    fn nonce_constructor_matches_live_reference_bytes() {
        use sha2::{Digest, Sha256};
        let (payer, nonce, dest, value) = reference_parties();
        let msg = nonce_transfer_message(payer, nonce, dest, 1_000_000, value).unwrap();
        let bytes = msg.serialize();
        // 224 bytes observed on the wire from the solana CLI build.
        assert_eq!(bytes.len(), 224);
        // SHA-256 of the exact bytes the CLI produced and the validator
        // settled. Any encoding drift fails here first.
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "623f1d88230ad3a7d2522298947df5b19e7dc7f1f4e54e89a20c98f683700206"
        );
    }

    #[test]
    fn nonce_constructor_refuses_role_collisions_and_zero() {
        let (payer, nonce, dest, value) = reference_parties();
        assert_eq!(
            nonce_transfer_message(nonce, nonce, dest, 1, value).unwrap_err(),
            SystemTransferError::AmbiguousNonceAccount
        );
        assert_eq!(
            nonce_transfer_message(payer, nonce, payer, 1, value).unwrap_err(),
            SystemTransferError::DestinationIsSource
        );
        assert_eq!(
            nonce_transfer_message(payer, nonce, dest, 0, value).unwrap_err(),
            SystemTransferError::ZeroLamports
        );
    }
}
