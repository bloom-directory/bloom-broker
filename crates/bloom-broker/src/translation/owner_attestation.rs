//! Broker-owned Petal registration projected onto Signer's generic attestation.

use bloom_broker_api as north;
use bloom_signer_api as south;

pub(crate) fn terms_to_signer(
    value: &north::PetalRegistrationTerms,
    authority_edge_digest: north::Digest32,
) -> Result<south::OwnerAttestationTerms, north::ProtocolError> {
    Ok(south::OwnerAttestationTerms {
        schema: north::Token::new(south::OWNER_ATTESTATION_SCHEMA)?,
        operation_id: value.operation_id.clone(),
        owner_wallet_id: value.owner_wallet_id.clone(),
        authority_edge_digest,
        context_digest: north::petal_registration_context_digest(),
        subject_digest: value.digest()?,
    })
}

pub(crate) fn receipt_to_broker(
    value: south::OwnerAttestationReceipt,
) -> north::PetalRegistrationReceipt {
    north::PetalRegistrationReceipt {
        operation_id: value.operation_id,
        ceremony_id: value.ceremony_id,
        owner_wallet_id: value.owner_wallet_id,
        authority_edge_digest: value.authority_edge_digest,
        context_digest: value.context_digest,
        subject_digest: value.subject_digest,
        receipt_digest: value.receipt_digest,
        signer_key_id: value.signer_key_id,
        signer_signature: value.signer_signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_terms_send_only_generic_attestation_fields() {
        let terms: north::PetalRegistrationTerms = serde_json::from_value(serde_json::json!({
            "schema":"bloom.petal-registration/1",
            "operation_id":"11".repeat(32),
            "enrollment_digest":"22".repeat(32),
            "owner_wallet_id":"owner",
            "package_hash":"33".repeat(32),
            "manifest_digest":"44".repeat(32),
            "permissions_digest":"55".repeat(32),
            "lineage_id":format!("pln1_{}", "a".repeat(52)),
        }))
        .unwrap();
        let mapped = terms_to_signer(&terms, north::Digest32::from_bytes([0x66; 32])).unwrap();
        let encoded = serde_json::to_value(&mapped).unwrap();
        assert_eq!(mapped.subject_digest, terms.digest().unwrap());
        assert_eq!(
            mapped.context_digest,
            north::petal_registration_context_digest()
        );
        assert_eq!(
            mapped.authority_edge_digest,
            north::Digest32::from_bytes([0x66; 32])
        );
        for forbidden in [
            "package_hash",
            "manifest_digest",
            "permissions_digest",
            "lineage_id",
            "enrollment_digest",
        ] {
            assert!(encoded.get(forbidden).is_none(), "{forbidden}");
        }
    }
}
