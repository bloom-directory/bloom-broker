use serde::{Deserialize, Serialize};

use crate::{Base64UrlBytes, ProtocolError, ProtocolErrorCode};

pub const SINGLE_PAYLOAD_MAX_BYTES: usize = 256 * 1024;
pub const BATCH_CHILD_MAX_BYTES: usize = 64 * 1024;
pub const BATCH_AGGREGATE_MAX_BYTES: usize = 512 * 1024;
pub const BATCH_CHILD_MAX_COUNT: usize = 32;
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningPayloads {
    Single { payload: Base64UrlBytes },
    Batch { children: Vec<Base64UrlBytes> },
}

impl<'de> Deserialize<'de> for SigningPayloads {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Unchecked {
            Single { payload: Base64UrlBytes },
            Batch { children: Vec<Base64UrlBytes> },
        }

        let payloads = match Unchecked::deserialize(deserializer)? {
            Unchecked::Single { payload } => Self::Single { payload },
            Unchecked::Batch { children } => Self::Batch { children },
        };
        payloads.validate().map_err(serde::de::Error::custom)?;
        Ok(payloads)
    }
}

impl SigningPayloads {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Single { payload } => {
                if payload.decode().len() > SINGLE_PAYLOAD_MAX_BYTES {
                    return Err(limit("single decoded payload exceeds 256 KiB"));
                }
            }
            Self::Batch { children } => {
                if children.is_empty() || children.len() > BATCH_CHILD_MAX_COUNT {
                    return Err(limit("batch must contain 1-32 children"));
                }
                let mut aggregate = 0usize;
                for child in children {
                    let length = child.decode().len();
                    if length > BATCH_CHILD_MAX_BYTES {
                        return Err(limit("decoded batch child exceeds 64 KiB"));
                    }
                    aggregate = aggregate
                        .checked_add(length)
                        .ok_or_else(|| limit("decoded batch aggregate overflow"))?;
                }
                if aggregate > BATCH_AGGREGATE_MAX_BYTES {
                    return Err(limit("decoded batch aggregate exceeds 512 KiB"));
                }
            }
        }
        Ok(())
    }
}

fn limit(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::LimitExceededFrame, message)
}
