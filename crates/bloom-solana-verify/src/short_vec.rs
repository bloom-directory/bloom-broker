//! Strict short-vector length prefix (Solana `ShortU16`).
//!
//! Solana length-prefixes every variable-length container (account keys,
//! instruction list, per-instruction account indices, and instruction data)
//! with a compact little-endian 7-bit encoding. Values below `0x7f` take one
//! byte; larger values use up to three bytes, each carrying seven bits with
//! the high bit set as a continuation marker.
//!
//! The decoder is strict and rejects non-canonical encodings: alias forms
//! (a redundant zero continuation byte), more than three bytes, and a
//! continuation marker on the third byte.

use thiserror::Error;

/// Maximum number of bytes a canonical `ShortU16` may occupy.
pub const SHORT_VEC_MAX_LEN_BYTES: usize = 3;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShortVecError {
    #[error("short-vec length alias encoding (non-canonical trailing zero)")]
    Alias,
    #[error("short-vec length overflow (exceeds u16)")]
    Overflow,
    #[error("short-vec length exceeds three bytes")]
    TooLong,
    #[error("short-vec continuation marker on third byte")]
    ByteThreeContinues,
    #[error("short-vec truncated: {0}")]
    Truncated(&'static str),
}

/// Read a canonical `ShortU16` length prefix from `bytes` starting at
/// `offset`. Returns the decoded value and the offset just past the prefix.
///
/// This mirrors the strict form accepted by `solana-short-vec`: a zero byte
/// in a non-leading position is an alias, a third byte may not carry a
/// continuation bit, and the decoded value must fit a `u16`.
pub fn read_short_vec(bytes: &[u8], offset: &mut usize) -> Result<u16, ShortVecError> {
    let mut value: u32 = 0;
    for nth in 0..SHORT_VEC_MAX_LEN_BYTES {
        let elem = *bytes
            .get(*offset)
            .ok_or(ShortVecError::Truncated("length prefix"))?;
        *offset += 1;

        if elem == 0 && nth != 0 {
            return Err(ShortVecError::Alias);
        }
        let elem_val = u32::from(elem & 0x7f);
        let done = elem & 0x80 == 0;

        if nth == SHORT_VEC_MAX_LEN_BYTES - 1 && !done {
            return Err(ShortVecError::ByteThreeContinues);
        }

        let shift = nth.saturating_mul(7);
        let shifted = elem_val
            .checked_shl(shift as u32)
            .ok_or(ShortVecError::Overflow)?;
        value = value.checked_add(shifted).ok_or(ShortVecError::Overflow)?;
        if u16::try_from(value).is_err() {
            return Err(ShortVecError::Overflow);
        }
        if done {
            return Ok(value as u16);
        }
    }
    Err(ShortVecError::TooLong)
}

/// Write a canonical `ShortU16` length prefix into `out`.
pub fn write_short_vec(out: &mut Vec<u8>, value: u16) {
    let mut rem = value;
    loop {
        let mut elem = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            out.push(elem);
            break;
        } else {
            elem |= 0x80;
            out.push(elem);
        }
    }
}

/// Read a length prefix and then exactly `len` bytes, returning the slice.
pub fn read_short_vec_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    what: &'static str,
) -> Result<&'a [u8], ShortVecError> {
    let len = read_short_vec(bytes, offset)? as usize;
    let end = offset.checked_add(len).ok_or(ShortVecError::Overflow)?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(ShortVecError::Truncated(what))?;
    *offset = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: u16) {
        let mut buf = Vec::new();
        write_short_vec(&mut buf, v);
        let mut off = 0;
        let got = read_short_vec(&buf, &mut off).unwrap();
        assert_eq!(got, v, "roundtrip failed for {v}");
        assert_eq!(off, buf.len(), "no trailing bytes for {v}");
    }

    #[test]
    fn roundtrip_boundaries() {
        for v in [
            0u16, 1, 0x7f, 0x80, 0xff, 0x100, 0x3fff, 0x4000, 0x7fff, 0x8000, 0xffff,
        ] {
            roundtrip(v);
        }
    }

    #[test]
    fn canonical_encoding_is_minimal() {
        // 0x7f fits in one byte.
        let mut buf = Vec::new();
        write_short_vec(&mut buf, 0x7f);
        assert_eq!(buf, vec![0x7f]);
        // 0x80 needs two bytes: 0x80 0x01.
        buf.clear();
        write_short_vec(&mut buf, 0x80);
        assert_eq!(buf, vec![0x80, 0x01]);
        // 0x3fff is the max two-byte value.
        buf.clear();
        write_short_vec(&mut buf, 0x3fff);
        assert_eq!(buf, vec![0xff, 0x7f]);
    }

    #[test]
    fn rejects_alias_encoding() {
        // 0x80 encoded as 0x80 0x00 is an alias.
        let buf = [0x80u8, 0x00];
        let mut off = 0;
        assert_eq!(
            read_short_vec(&buf, &mut off).unwrap_err(),
            ShortVecError::Alias
        );
    }

    #[test]
    fn rejects_byte_three_continuation() {
        // Third byte with continuation bit set.
        let buf = [0xffu8, 0xff, 0xff];
        let mut off = 0;
        assert_eq!(
            read_short_vec(&buf, &mut off).unwrap_err(),
            ShortVecError::ByteThreeContinues
        );
    }

    #[test]
    fn rejects_truncated() {
        let buf = [0x80u8];
        let mut off = 0;
        assert!(matches!(
            read_short_vec(&buf, &mut off).unwrap_err(),
            ShortVecError::Truncated(_)
        ));
    }
}
