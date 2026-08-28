use std::collections::HashSet;

use crate::{ProtocolError, ProtocolErrorCode};

/// Reject an empty, oversized, or control-character-bearing display field.
pub(crate) fn validate_display_identity(
    field: &str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            format!(
                "{field} must contain 1-{maximum_bytes} UTF-8 bytes without control characters"
            ),
        ));
    }
    Ok(())
}

/// True when every element of `values` is distinct.
pub(crate) fn all_unique<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().all(|value| seen.insert(value))
}
