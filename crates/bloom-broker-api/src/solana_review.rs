//! Pump signing scope identifiers and the Machine's blockhash-independent
//! retry identity. Broker uses its separate complete message parser to verify
//! the owner-reviewed binding; this helper is not a semantic verifier.

use crate::{Digest32, ProtocolError, ProtocolErrorCode};
use sha2::{Digest, Sha256};

pub const PUMPFUN_REVIEW_OPERATION_CLASSES: &[&str] = &[
    "pumpfun.buy",
    "pumpfun.sell",
    "pumpfun.close_token_account",
    "pumpfun.launch",
];

pub fn pumpfun_review_required(class: &str) -> bool {
    PUMPFUN_REVIEW_OPERATION_CLASSES.contains(&class)
}

/// Bind all message bytes except its 32-byte recent blockhash. Full parsing
/// and signature/account/instruction validation belong to Broker.
pub fn solana_message_binding(bytes: &[u8]) -> Result<Digest32, ProtocolError> {
    let invalid = || {
        ProtocolError::new(
            ProtocolErrorCode::ClaimInvalid,
            "Solana review requires a bounded legacy or v0 transaction message",
        )
    };
    if bytes.is_empty() || bytes.len() > 1232 {
        return Err(invalid());
    }
    let prefix = if bytes[0] & 0x80 != 0 {
        if bytes[0] != 0x80 {
            return Err(invalid());
        }
        1
    } else {
        0
    };
    let mut cursor = prefix + 3;
    let first = *bytes.get(cursor).ok_or_else(invalid)?;
    cursor += 1;
    let accounts = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let second = *bytes.get(cursor).ok_or_else(invalid)?;
        cursor += 1;
        if second == 0 || second & 0x80 != 0 {
            return Err(invalid());
        }
        usize::from(first & 0x7f) | (usize::from(second) << 7)
    };
    if accounts == 0 || accounts > 256 {
        return Err(invalid());
    }
    let start = cursor + accounts * 32;
    let end = start + 32;
    let mut normalized = bytes.to_vec();
    normalized.get_mut(start..end).ok_or_else(invalid)?.fill(0);
    let mut hash = Sha256::new();
    hash.update(b"bloom.solana.blockhash-independent.v1\0");
    hash.update(normalized);
    Ok(Digest32::from_bytes(hash.finalize().into()))
}
