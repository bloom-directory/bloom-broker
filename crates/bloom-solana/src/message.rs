//! Canonical Solana legacy transaction message codec.
//!
//! A legacy `Message` serializes, in order:
//!
//! ```text
//! header       3 bytes: num_required_signatures, num_readonly_signed_accounts,
//!                       num_readonly_unsigned_accounts
//! account_keys short-vec of 32-byte public keys
//! blockhash    32 bytes
//! instructions short-vec of CompiledInstruction {
//!                  program_id_index: u8
//!                  accounts:         short-vec of u8 (indices into account_keys)
//!                  data:             short-vec of u8
//!              }
//! ```
//!
//! The first byte of a legacy message (`num_required_signatures`) must have
//! its high bit clear: the value `0x80` and above denotes a versioned message
//! (v0 / address-lookup-table), which this crate rejects.
//!
//! Parsing is strict: it rejects non-canonical short vectors, out-of-range
//! account/program indices, a program occupying the fee-payer slot, and any
//! trailing bytes after the message.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pubkey::{PUBKEY_BYTES, Pubkey};
use crate::short_vec::{self, ShortVecError};

/// The `num_required_signatures` bit that marks a versioned (non-legacy)
/// message. Legacy messages always have this bit clear.
pub const MESSAGE_VERSION_PREFIX: u8 = 0x80;

/// Maximum accounts in a legacy message (bounded by the `u16` short-vec
/// length and the 128-byte header requirement).
pub const MAX_ACCOUNT_KEYS: usize = 256;

/// Fixed serialized length of the three header bytes.
pub const MESSAGE_HEADER_LENGTH: usize = 3;

/// The three-byte message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Number of signer accounts, which are the first `num_required_signatures`
    /// entries of `account_keys`. The fee payer is always `account_keys[0]`.
    pub num_required_signatures: u8,
    /// Number of the trailing signer accounts that are read-only.
    pub num_readonly_signed_accounts: u8,
    /// Number of the trailing unsigned accounts that are read-only.
    pub num_readonly_unsigned_accounts: u8,
}

impl MessageHeader {
    pub const BYTES: usize = 3;
}

/// A compact encoding of one instruction within a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledInstruction {
    /// Index into `account_keys` of the program that executes this instruction.
    pub program_id_index: u8,
    /// Ordered indices into `account_keys` of the accounts passed to the program.
    pub accounts: Vec<u8>,
    /// The program input data.
    pub data: Vec<u8>,
}

/// A decoded legacy message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyMessage {
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

impl LegacyMessage {
    /// The fee payer public key (`account_keys[0]`).
    pub fn fee_payer(&self) -> Pubkey {
        self.account_keys[0]
    }

    /// Serialize to the canonical byte encoding.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 32 * self.account_keys.len());
        out.push(self.header.num_required_signatures);
        out.push(self.header.num_readonly_signed_accounts);
        out.push(self.header.num_readonly_unsigned_accounts);
        short_vec::write_short_vec(&mut out, self.account_keys.len() as u16);
        for key in &self.account_keys {
            out.extend_from_slice(key.as_bytes());
        }
        out.extend_from_slice(&self.recent_blockhash);
        short_vec::write_short_vec(&mut out, self.instructions.len() as u16);
        for ix in &self.instructions {
            out.push(ix.program_id_index);
            short_vec::write_short_vec(&mut out, ix.accounts.len() as u16);
            out.extend_from_slice(&ix.accounts);
            short_vec::write_short_vec(&mut out, ix.data.len() as u16);
            out.extend_from_slice(&ix.data);
        }
        out
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("short-vec: {0}")]
    ShortVec(#[from] ShortVecError),
    #[error("message is truncated")]
    Truncated,
    #[error("message is empty")]
    Empty,
    #[error("versioned message (v0 / address-lookup-table) is not supported")]
    Versioned,
    #[error("trailing bytes after message ({0} bytes)")]
    TrailingBytes(usize),
    #[error("no fee payer: num_required_signatures is 0")]
    NoFeePayer,
    #[error("read-only signed accounts overlap with writable signers")]
    ReadonlySignerOverlap,
    #[error("num_required_signatures + num_readonly_unsigned_accounts exceeds account count")]
    SignerUnsignedOverlap,
    #[error("instruction program_id_index {0} is out of range")]
    ProgramIndexOutOfRange(u8),
    #[error("instruction program_id_index 0: the program cannot be the fee payer")]
    ProgramIsFeePayer,
    #[error("instruction account index {0} is out of range")]
    AccountIndexOutOfRange(u8),
    #[error("account count {0} exceeds the legacy maximum")]
    TooManyAccounts(usize),
}

/// Strictly parse a canonical legacy message from bytes.
///
/// No trailing bytes are permitted. This is the verifier's parser and must
/// remain independent of the driver's construction code.
pub fn parse_message(bytes: &[u8]) -> Result<LegacyMessage, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }
    // A legacy message's first byte has the version bit clear.
    if bytes[0] & MESSAGE_VERSION_PREFIX != 0 {
        return Err(ParseError::Versioned);
    }

    let mut offset = 0usize;

    let num_required_signatures = *bytes.get(offset).ok_or(ParseError::Truncated)?;
    offset += 1;
    let num_readonly_signed_accounts = *bytes.get(offset).ok_or(ParseError::Truncated)?;
    offset += 1;
    let num_readonly_unsigned_accounts = *bytes.get(offset).ok_or(ParseError::Truncated)?;
    offset += 1;

    let header = MessageHeader {
        num_required_signatures,
        num_readonly_signed_accounts,
        num_readonly_unsigned_accounts,
    };

    let account_count = short_vec::read_short_vec(bytes, &mut offset)? as usize;
    if account_count > MAX_ACCOUNT_KEYS {
        return Err(ParseError::TooManyAccounts(account_count));
    }
    let mut account_keys = Vec::with_capacity(account_count);
    for _ in 0..account_count {
        let raw = bytes
            .get(offset..offset + PUBKEY_BYTES)
            .ok_or(ParseError::Truncated)?;
        offset += PUBKEY_BYTES;
        let mut arr = [0u8; PUBKEY_BYTES];
        arr.copy_from_slice(raw);
        account_keys.push(Pubkey::from_bytes(arr));
    }

    let mut recent_blockhash = [0u8; 32];
    let hash_bytes = bytes
        .get(offset..offset + 32)
        .ok_or(ParseError::Truncated)?;
    recent_blockhash.copy_from_slice(hash_bytes);
    offset += 32;

    let instruction_count = short_vec::read_short_vec(bytes, &mut offset)? as usize;
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program_id_index = *bytes.get(offset).ok_or(ParseError::Truncated)?;
        offset += 1;
        let accounts =
            short_vec::read_short_vec_bytes(bytes, &mut offset, "instruction accounts")?.to_vec();
        let data =
            short_vec::read_short_vec_bytes(bytes, &mut offset, "instruction data")?.to_vec();
        instructions.push(CompiledInstruction {
            program_id_index,
            accounts,
            data,
        });
    }

    if offset != bytes.len() {
        return Err(ParseError::TrailingBytes(bytes.len() - offset));
    }

    let message = LegacyMessage {
        header,
        account_keys,
        recent_blockhash,
        instructions,
    };
    message.sanitize()?;
    Ok(message)
}

impl LegacyMessage {
    /// Structural validity checks mirroring the Solana `Message::sanitize`.
    fn sanitize(&self) -> Result<(), ParseError> {
        if self.header.num_required_signatures == 0 {
            return Err(ParseError::NoFeePayer);
        }
        if self.header.num_readonly_signed_accounts >= self.header.num_required_signatures {
            return Err(ParseError::ReadonlySignerOverlap);
        }
        let n = self.header.num_required_signatures as usize
            + self.header.num_readonly_unsigned_accounts as usize;
        if n > self.account_keys.len() {
            return Err(ParseError::SignerUnsignedOverlap);
        }
        for ix in &self.instructions {
            if ix.program_id_index as usize >= self.account_keys.len() {
                return Err(ParseError::ProgramIndexOutOfRange(ix.program_id_index));
            }
            if ix.program_id_index == 0 {
                return Err(ParseError::ProgramIsFeePayer);
            }
            for a in &ix.accounts {
                if *a as usize >= self.account_keys.len() {
                    return Err(ParseError::AccountIndexOutOfRange(*a));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_versioned_prefix() {
        let mut bytes = vec![0u8; 100];
        bytes[0] = 0x80;
        assert_eq!(parse_message(&bytes).unwrap_err(), ParseError::Versioned);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(parse_message(&[]).unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn rejects_trailing_bytes() {
        // A valid header-less minimal message is hard to construct by hand;
        // instead assert that appending a byte to a valid message is rejected
        // by the round-trip test below.
        let msg = LegacyMessage {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![Pubkey::from_bytes([1u8; 32])],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
        };
        let mut bytes = msg.serialize();
        bytes.push(0x00);
        assert!(matches!(
            parse_message(&bytes).unwrap_err(),
            ParseError::TrailingBytes(1)
        ));
    }
}
