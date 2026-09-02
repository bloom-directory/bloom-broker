//! Custody requests and public result projections.

use bloom_broker_api as north;
use bloom_signer_api as south;

use super::{ceremony, delegated, key, policy};

pub(crate) fn petal_scope_to_signer(
    value: north::PetalKeyScope,
) -> Result<south::DelegatedKeyScope, north::ProtocolError> {
    let allowed_resource_ids = value
        .allowed_routes
        .iter()
        .map(|route| delegated::resource_id(route))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(south::DelegatedKeyScope {
        wallet_id: value.wallet_id,
        parent_key_ref: key::key_ref_to_signer(value.parent_key_ref),
        authority_id: delegated::authority_id(&value.lineage_id)?,
        active_subject_id: value.package_hash,
        delegate_id: value.key_slot,
        allowed_resource_ids,
        allowed_operation_classes: value.allowed_operation_classes,
        allowed_crypto_suites: value
            .allowed_crypto_suites
            .into_iter()
            .map(key::crypto_suite_to_signer)
            .collect(),
        maximum_lifetime_ms: value.maximum_lifetime_ms,
        custody_operation_id: value.custody_operation_id,
    })
}

fn legacy_migration_to_signer(
    value: north::LegacyPasskeyMigrationPublic,
) -> south::LegacyPasskeyMigrationPublic {
    south::LegacyPasskeyMigrationPublic {
        schema: value.schema,
        wallet_name: value.wallet_name,
        address: value.address,
        public_key_fingerprint: value.public_key_fingerprint,
        credential_id_fingerprint: value.credential_id_fingerprint,
        legacy_format_version: value.legacy_format_version,
        bundle_digest: value.bundle_digest,
        policy_mode: value.policy_mode,
    }
}

pub(crate) fn prepare_to_signer(
    value: north::CustodyPrepareRequest,
) -> Result<south::CustodyPrepareRequest, north::ProtocolError> {
    let delegated_key_scope = value
        .petal_key_scope
        .map(petal_scope_to_signer)
        .transpose()?;
    let exact_terms_digest = match &delegated_key_scope {
        Some(scope) => scope.request_digest().map_err(|error| {
            north::ProtocolError::new(north::ProtocolErrorCode::MalformedFrame, error.to_string())
        })?,
        None => value.exact_terms_digest,
    };
    Ok(south::CustodyPrepareRequest {
        ceremony_kind: ceremony::kind_to_signer(value.ceremony_kind)?,
        custody_operation_id: value.custody_operation_id,
        wallet_id: value.wallet_id,
        key_ref: value.key_ref.map(key::key_ref_to_signer),
        exact_terms_digest,
        expected_input_class: value.expected_input_class,
        browser_output_recipient_key: value.browser_output_recipient_key,
        delegated_key_scope,
        legacy_passkey_migration: value
            .legacy_passkey_migration
            .map(legacy_migration_to_signer),
    })
}

pub(crate) fn result_to_machine(value: south::CustodyResult) -> north::CustodyResult {
    north::CustodyResult {
        ceremony_kind: ceremony::kind_to_machine(value.ceremony_kind),
        custody_operation_id: value.custody_operation_id,
        public_status: ceremony::state_to_machine(value.public_status),
        wallet_id: value.wallet_id,
        public_key_refs: value
            .public_key_refs
            .into_iter()
            .map(key::key_ref_to_machine)
            .collect(),
        credential_summaries: value
            .credential_summaries
            .into_iter()
            .map(|credential| north::CredentialSummary {
                credential_id: credential.credential_id,
                rp_id: credential.rp_id,
                active: credential.active,
            })
            .collect(),
        initial_policy: value.initial_policy.map(policy::snapshot_to_machine),
        receipt_digest: value.receipt_digest,
        encrypted_browser_result: value.encrypted_browser_result.map(|encrypted| {
            north::EncryptedBrowserResult {
                kem_output: encrypted.kem_output,
                ciphertext: encrypted.ciphertext,
            }
        }),
        signer_key_id: value.signer_key_id,
        signer_signature: value.signer_signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> north::Digest32 {
        north::Digest32::from_bytes([byte; 32])
    }

    fn operation(byte: u8) -> north::OperationId {
        north::OperationId::from_bytes([byte; 32])
    }

    fn north_key(locator: &str, fingerprint: u8) -> north::KeyRef {
        north::KeyRef {
            backend: north::Token::new("local").unwrap(),
            backend_instance: north::Token::new("instance").unwrap(),
            locator: locator.into(),
            key_spec: north::KeySpec::Secp256k1,
            public_key_fingerprint: digest(fingerprint),
            derivation: None,
        }
    }

    #[test]
    fn scoped_custody_request_preserves_every_binding() {
        let scope = north::PetalKeyScope {
            wallet_id: north::Token::new("wallet-1").unwrap(),
            parent_key_ref: north_key("parent-2", 3),
            package_hash: digest(4),
            route: "/route-5".into(),
            lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            key_slot: north::Token::new("agent-6").unwrap(),
            allowed_routes: vec!["/route-5".into(), "/route-6".into()],
            allowed_operation_classes: vec![north::Token::new("purpose-7").unwrap()],
            allowed_crypto_suites: vec![north::CryptoSuite::Secp256k1Sha256Recoverable],
            maximum_lifetime_ms: north::DecimalU64::new(8),
            custody_operation_id: operation(9),
        };
        let request = north::CustodyPrepareRequest {
            ceremony_kind: north::CeremonyKind::KeyDerive,
            custody_operation_id: operation(9),
            wallet_id: Some(north::Token::new("wallet-1").unwrap()),
            key_ref: Some(north_key("parent-2", 3)),
            exact_terms_digest: scope.request_digest().unwrap(),
            expected_input_class: north::Token::new("scope-10").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: Some(scope),
            legacy_passkey_migration: None,
        };
        request.validate_petal_key_scope_binding().unwrap();
        let mut inconsistent = request.clone();
        inconsistent
            .petal_key_scope
            .as_mut()
            .unwrap()
            .custody_operation_id = operation(11);
        assert_eq!(
            inconsistent
                .validate_petal_key_scope_binding()
                .unwrap_err()
                .code,
            north::ProtocolErrorCode::OperationIdConflict
        );
        let mapped = prepare_to_signer(request).unwrap();
        mapped.validate_delegated_key_scope_binding().unwrap();
        let mapped_scope = mapped.delegated_key_scope.unwrap();
        assert_eq!(mapped.ceremony_kind, south::CeremonyKind::KeyDerive);
        assert_eq!(mapped.custody_operation_id, operation(9));
        assert_eq!(mapped.wallet_id.unwrap().as_str(), "wallet-1");
        assert_eq!(mapped.key_ref.unwrap().locator, "parent-2");
        assert_eq!(
            mapped.exact_terms_digest,
            mapped_scope.request_digest().unwrap()
        );
        assert_eq!(mapped.expected_input_class.as_str(), "scope-10");
        assert_eq!(mapped_scope.active_subject_id, digest(4));
        assert_eq!(
            mapped_scope.parent_key_ref.public_key_fingerprint,
            digest(3)
        );
        assert_eq!(mapped_scope.delegate_id.as_str(), "agent-6");
        assert_eq!(
            mapped_scope.authority_id,
            delegated::authority_id("pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap()
        );
        assert_eq!(
            mapped_scope.allowed_resource_ids,
            [
                delegated::resource_id("/route-5").unwrap(),
                delegated::resource_id("/route-6").unwrap()
            ]
        );
        assert_eq!(
            mapped_scope.allowed_operation_classes[0].as_str(),
            "purpose-7"
        );
        assert_eq!(mapped_scope.maximum_lifetime_ms.get(), 8);
        assert_eq!(
            mapped_scope.allowed_crypto_suites,
            [south::CryptoSuite::Secp256k1Sha256Recoverable]
        );
        assert_eq!(mapped_scope.custody_operation_id, operation(9));

        let mut substituted = mapped_scope;
        substituted.custody_operation_id = operation(11);
        assert_ne!(substituted.digest().unwrap(), mapped.exact_terms_digest);
    }

    #[test]
    fn legacy_migration_request_preserves_every_public_binding() {
        let operation_id = operation(41);
        let migration = north::LegacyPasskeyMigrationPublic {
            schema: north::Token::new("bloom.legacy_passkey_migration_receipt.v1").unwrap(),
            wallet_name: north::Token::new("legacy-wallet").unwrap(),
            address: "0x1111111111111111111111111111111111111111".into(),
            public_key_fingerprint: digest(42),
            credential_id_fingerprint: digest(43),
            legacy_format_version: 1,
            bundle_digest: digest(44),
            policy_mode: north::Token::new("restrictive_current_policy").unwrap(),
        };
        let request = north::CustodyPrepareRequest {
            ceremony_kind: north::CeremonyKind::WalletImport,
            custody_operation_id: operation_id.clone(),
            wallet_id: None,
            key_ref: None,
            exact_terms_digest: migration.terms_digest(&operation_id).unwrap(),
            expected_input_class: north::Token::new("legacy_passkey_v1_prf").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: Some(migration.clone()),
        };
        request.validate_legacy_passkey_migration_binding().unwrap();
        let mapped = prepare_to_signer(request).unwrap();
        mapped.validate_legacy_passkey_migration_binding().unwrap();
        let mapped_migration = mapped.legacy_passkey_migration.unwrap();
        assert_eq!(mapped_migration.wallet_name, migration.wallet_name);
        assert_eq!(mapped_migration.address, migration.address);
        assert_eq!(
            mapped_migration.public_key_fingerprint,
            migration.public_key_fingerprint
        );
        assert_eq!(
            mapped_migration.credential_id_fingerprint,
            migration.credential_id_fingerprint
        );
        assert_eq!(mapped_migration.bundle_digest, migration.bundle_digest);
        assert_eq!(mapped_migration.policy_mode, migration.policy_mode);
    }

    #[test]
    fn custody_result_preserves_receipt_signature_and_encrypted_output() {
        let result = south::CustodyResult {
            ceremony_kind: south::CeremonyKind::WalletExport,
            custody_operation_id: operation(12),
            public_status: south::CeremonyState::Succeeded,
            wallet_id: Some(south::Token::new("wallet-13").unwrap()),
            public_key_refs: vec![south::KeyRef {
                backend: south::Token::new("backend-14").unwrap(),
                backend_instance: south::Token::new("instance-15").unwrap(),
                locator: "key-16".into(),
                key_spec: south::KeySpec::Secp256k1,
                public_key_fingerprint: digest(17),
                derivation: None,
            }],
            credential_summaries: vec![south::CredentialSummary {
                credential_id: south::Base64UrlBytes::from_bytes(&[18]),
                rp_id: south::Token::new("rp-19").unwrap(),
                active: true,
            }],
            initial_policy: Some(south::SignedPolicySnapshot {
                wallet_id: south::Token::new("wallet-13").unwrap(),
                version: south::DecimalU64::new(20),
                canonical_policy: south::Base64UrlBytes::from_bytes(&[21]),
                policy_digest: digest(22),
                policy_signing_key_id: south::Token::new("policy-key-23").unwrap(),
                policy_verifying_key: south::Base64UrlBytes::from_bytes(&[24]),
                signer_signature: south::Base64UrlBytes::from_bytes(&[25]),
            }),
            receipt_digest: digest(26),
            encrypted_browser_result: Some(south::HpkeEnvelope {
                kem_output: south::Base64UrlBytes::from_bytes(&[27]),
                ciphertext: south::Base64UrlBytes::from_bytes(&[28]),
            }),
            signer_key_id: south::Token::new("signer-key-29").unwrap(),
            signer_signature: south::Base64UrlBytes::from_bytes(&[30]),
        };
        let mapped = result_to_machine(result);
        assert_eq!(mapped.ceremony_kind, north::CeremonyKind::WalletExport);
        assert_eq!(mapped.custody_operation_id, operation(12));
        assert_eq!(mapped.public_status, north::CeremonyState::Succeeded);
        assert_eq!(mapped.wallet_id.unwrap().as_str(), "wallet-13");
        assert_eq!(mapped.public_key_refs[0].public_key_fingerprint, digest(17));
        assert_eq!(
            mapped.credential_summaries[0].credential_id.decode(),
            vec![18]
        );
        assert_eq!(mapped.credential_summaries[0].rp_id.as_str(), "rp-19");
        assert!(mapped.credential_summaries[0].active);
        assert_eq!(mapped.initial_policy.unwrap().policy_digest, digest(22));
        assert_eq!(mapped.receipt_digest, digest(26));
        let encrypted = mapped.encrypted_browser_result.unwrap();
        assert_eq!(encrypted.kem_output.decode(), vec![27]);
        assert_eq!(encrypted.ciphertext.decode(), vec![28]);
        assert_eq!(mapped.signer_key_id.as_str(), "signer-key-29");
        assert_eq!(mapped.signer_signature.decode(), vec![30]);
    }
}
