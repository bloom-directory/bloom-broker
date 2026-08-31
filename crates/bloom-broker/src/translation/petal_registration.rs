//! Explicit translation of exact package registration terms.
use bloom_broker_api as north;
use bloom_signer_api as south;

pub(crate) fn terms_to_signer(
    value: north::PetalRegistrationTerms,
) -> south::PetalRegistrationTerms {
    south::PetalRegistrationTerms {
        schema: value.schema,
        operation_id: value.operation_id,
        enrollment_digest: value.enrollment_digest,
        owner_wallet_id: value.owner_wallet_id,
        package_hash: value.package_hash,
        manifest_digest: value.manifest_digest,
        permissions_digest: value.permissions_digest,
        lineage_id: value.lineage_id,
    }
}

#[cfg(test)]
fn terms_to_machine(value: south::PetalRegistrationTerms) -> north::PetalRegistrationTerms {
    north::PetalRegistrationTerms {
        schema: value.schema,
        operation_id: value.operation_id,
        enrollment_digest: value.enrollment_digest,
        owner_wallet_id: value.owner_wallet_id,
        package_hash: value.package_hash,
        manifest_digest: value.manifest_digest,
        permissions_digest: value.permissions_digest,
        lineage_id: value.lineage_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn petal_registration_terms_round_trip_preserves_digest_and_enrollment_vectors() {
        let original: north::PetalRegistrationTerms = serde_json::from_value(serde_json::json!({
            "schema":"bloom.petal-registration/1", "operation_id":"11".repeat(32),
            "enrollment_digest":"22".repeat(32), "owner_wallet_id":"wallet-owner",
            "package_hash":"33".repeat(32), "manifest_digest":"44".repeat(32),
            "permissions_digest":"55".repeat(32), "lineage_id":format!("pln1_{}", "a".repeat(52)),
        }))
        .unwrap();
        let translated = terms_to_signer(original.clone());
        assert_eq!(translated.digest().unwrap(), original.digest().unwrap());
        assert_eq!(terms_to_machine(translated.clone()), original);
        let broker_id = north::Token::new("broker-key").unwrap();
        let signer_id = north::Token::new("signer-key").unwrap();
        let broker_key = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let signer_key = SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert_eq!(
            north::petal_registration_enrollment_digest(
                &broker_id,
                &broker_key,
                &signer_id,
                &signer_key
            )
            .unwrap(),
            south::petal_registration_enrollment_digest(
                &broker_id,
                &broker_key,
                &signer_id,
                &signer_key
            )
            .unwrap()
        );
        let mut receipt: south::CustodyResult = serde_json::from_value(serde_json::json!({
            "ceremony_kind":"petal_registration", "custody_operation_id": translated.operation_id,
            "public_status":"SUCCEEDED", "wallet_id": translated.owner_wallet_id,
            "public_key_refs":[], "credential_summaries":[], "initial_policy":null,
            "receipt_digest":"66".repeat(32), "petal_registration_terms_digest": translated.digest().unwrap(),
            "encrypted_browser_result":null, "signer_key_id":"signer-key", "signer_signature":""
        })).unwrap();
        let key = SigningKey::from_bytes(&[2; 32]);
        let message = receipt.unsigned_canonical_bytes().unwrap();
        let signature = key.sign(&message);
        receipt.signer_signature = south::Base64UrlBytes::from_bytes(&signature.to_bytes());
        let mapped = super::super::custody::result_to_machine(receipt);
        assert_eq!(mapped.unsigned_canonical_bytes().unwrap(), message);
        mapped
            .validate_petal_registration_binding(&original)
            .unwrap();
        key.verifying_key()
            .verify_strict(&mapped.unsigned_canonical_bytes().unwrap(), &signature)
            .unwrap();
    }
}
