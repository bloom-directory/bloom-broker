use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{Base64UrlBytes, Digest32, ProtocolError, ProtocolErrorCode, Token};

pub const PROVENANCE_RECORD_SIGNATURE_DOMAIN: &[u8] = b"bloom-provenance-record/v1";
pub const PROVENANCE_CATALOG_SCHEMA: &str = "bloom.provenance-catalog.1";

/// Trusted runtime subject assertion supplied by authenticated Machine.
/// Broker resolves this subject against its own installer-signed catalog; the
/// Machine never supplies a record or signature for Broker to accept.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProvenanceSubject {
    Petal {
        package_hash: Digest32,
        route: String,
    },
    Cli {
        client_id: Token,
        command_class: Token,
    },
    System {
        component_id: Token,
        operation_class: Token,
    },
}

/// One installer-signed catalog record shared by Machine and Broker.
///
/// Machine uses the complete signed record only to bind its approval terms to
/// the installer-owned digest. Broker independently verifies the signature and
/// current catalog membership before preparing or authorizing an approval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub subject: ProvenanceSubject,
    pub publisher: Token,
    pub operation_classes: Vec<ProvenanceOperationClass>,
    pub installer_key_id: Token,
    pub installer_signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceOperationClass {
    pub operation_class: Token,
    pub fee_asset: Option<ProvenanceFeeAsset>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceFeeAsset {
    pub chain: Token,
    pub asset: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceCatalog {
    pub schema: String,
    pub records: Vec<ProvenanceRecord>,
}

impl ProvenanceRecord {
    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        let bytes = serde_jcs::to_vec(self).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("provenance record JCS encoding failed: {error}"),
            )
        })?;
        Ok(Digest32::from_bytes(Sha256::digest(bytes).into()))
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.installer_signature = Base64UrlBytes::from_bytes(&[]);
        serde_jcs::to_vec(&unsigned).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("provenance record JCS encoding failed: {error}"),
            )
        })
    }
}

impl ProvenanceCatalog {
    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        if self.schema != PROVENANCE_CATALOG_SCHEMA || self.records.is_empty() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnsupportedVersion,
                "provenance catalog schema is unsupported or empty",
            ));
        }
        let mut subjects = std::collections::HashSet::new();
        for record in &self.records {
            let subject = serde_jcs::to_vec(&record.subject).map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
            })?;
            if !subjects.insert(subject)
                || record.operation_classes.is_empty()
                || record
                    .operation_classes
                    .iter()
                    .any(|entry| entry.operation_class.as_str().is_empty())
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::ProvenanceMismatch,
                    "provenance catalog contains a duplicate subject or empty operation class",
                ));
            }
        }
        Ok(())
    }

    pub fn record(&self, subject: &ProvenanceSubject) -> Option<&ProvenanceRecord> {
        self.records
            .iter()
            .find(|record| &record.subject == subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(subject: ProvenanceSubject) -> ProvenanceRecord {
        ProvenanceRecord {
            subject,
            publisher: Token::new("bloom-installer").unwrap(),
            operation_classes: vec![ProvenanceOperationClass {
                operation_class: Token::new("transaction.confirm").unwrap(),
                fee_asset: None,
            }],
            installer_key_id: Token::new("installer-key").unwrap(),
            installer_signature: Base64UrlBytes::from_bytes(&[1; 64]),
        }
    }

    #[test]
    fn catalog_is_closed_nonempty_and_unique_by_subject() {
        let subject = ProvenanceSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("transaction.confirm").unwrap(),
        };
        let mut catalog = ProvenanceCatalog {
            schema: PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![record(subject.clone())],
        };
        catalog.validate_shape().unwrap();
        assert_eq!(catalog.record(&subject), Some(&catalog.records[0]));

        catalog.records.push(record(subject));
        assert_eq!(
            catalog.validate_shape().unwrap_err().code,
            ProtocolErrorCode::ProvenanceMismatch
        );
    }

    #[test]
    fn digest_binds_the_installer_signature_but_signature_input_does_not() {
        let subject = ProvenanceSubject::System {
            component_id: Token::new("bloom-machine").unwrap(),
            operation_class: Token::new("transaction.confirm").unwrap(),
        };
        let mut first = record(subject);
        let unsigned = first.unsigned_canonical_bytes().unwrap();
        let digest = first.digest().unwrap();
        first.installer_signature = Base64UrlBytes::from_bytes(&[2; 64]);
        assert_eq!(first.unsigned_canonical_bytes().unwrap(), unsigned);
        assert_ne!(first.digest().unwrap(), digest);
    }
}
