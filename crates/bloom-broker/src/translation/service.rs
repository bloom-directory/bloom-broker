//! Public registry and status projections returned through Broker.

use bloom_broker_api as north;
use bloom_signer_api as south;

use super::key;

pub(crate) fn wallet_request_to_signer(value: north::WalletRequest) -> south::WalletRequest {
    south::WalletRequest {
        wallet_id: value.wallet_id,
    }
}

pub(crate) fn key_request_to_signer(value: north::KeyRequest) -> south::KeyRequest {
    south::KeyRequest {
        key_ref: key::key_ref_to_signer(value.key_ref),
    }
}

pub(crate) fn key_to_machine(value: south::KeyPublic) -> north::KeyPublic {
    north::KeyPublic {
        key_ref: key::key_ref_to_machine(value.key_ref),
        role: match value.role {
            south::KeyRole::WalletRoot => north::KeyRole::WalletRoot,
            south::KeyRole::Derived => north::KeyRole::Derived,
        },
        canonical_public_key: value.canonical_public_key,
        addresses: value.addresses,
        supported_crypto_suites: value
            .supported_crypto_suites
            .into_iter()
            .map(key::crypto_suite_to_machine)
            .collect(),
    }
}

pub(crate) fn credential_to_machine(value: south::CredentialPublic) -> north::CredentialPublic {
    north::CredentialPublic {
        credential_id: value.credential_id,
        wallet_id: value.wallet_id,
        created_at_ms: value.created_at_ms,
        state: match value.state {
            south::CredentialState::Active => north::CredentialState::Active,
            south::CredentialState::Revoked => north::CredentialState::Revoked,
        },
    }
}

pub(crate) fn readiness_to_machine(value: south::Readiness) -> north::Readiness {
    north::Readiness {
        service_id: value.service_id,
        service_version: value.service_version,
        build_digest: value.build_digest,
        boot_epoch: value.boot_epoch,
        state: match value.state {
            south::ReadinessState::Ready => north::ReadinessState::Ready,
            south::ReadinessState::DegradedReadOnly => north::ReadinessState::DegradedReadOnly,
            south::ReadinessState::Unavailable => north::ReadinessState::Unavailable,
        },
        conditions: value.conditions,
    }
}

pub(crate) fn approval_status_to_signer(
    value: north::ApprovalPublicStatus,
) -> south::ApprovalPublicStatus {
    south::ApprovalPublicStatus {
        approval_id: value.approval_id,
        wallet_id: value.wallet_id,
        state: match value.state {
            north::ApprovalLifecycleState::Prepared => south::ApprovalLifecycleState::Prepared,
            north::ApprovalLifecycleState::AwaitingCeremony => {
                south::ApprovalLifecycleState::AwaitingCeremony
            }
            north::ApprovalLifecycleState::Orphaned => south::ApprovalLifecycleState::Orphaned,
            north::ApprovalLifecycleState::Active => south::ApprovalLifecycleState::Active,
            north::ApprovalLifecycleState::Exhausted => south::ApprovalLifecycleState::Exhausted,
            north::ApprovalLifecycleState::Expired => south::ApprovalLifecycleState::Expired,
            north::ApprovalLifecycleState::Revoked => south::ApprovalLifecycleState::Revoked,
            north::ApprovalLifecycleState::Cancelled => south::ApprovalLifecycleState::Cancelled,
            north::ApprovalLifecycleState::Failed => south::ApprovalLifecycleState::Failed,
        },
        effective_claim_assurance: value.effective_claim_assurance.map(
            |assurance| match assurance {
                north::ClaimAssuranceLevel::MachineAsserted => {
                    south::ClaimAssuranceLevel::MachineAsserted
                }
                north::ClaimAssuranceLevel::ProofVerified => {
                    south::ClaimAssuranceLevel::ProofVerified
                }
                north::ClaimAssuranceLevel::InvariantAttested => {
                    south::ClaimAssuranceLevel::InvariantAttested
                }
            },
        ),
        ceremony_url: value.ceremony_url,
        ceremony_expires_at_ms: value.ceremony_expires_at_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> north::Digest32 {
        north::Digest32::from_bytes([byte; 32])
    }

    #[test]
    fn key_credential_readiness_and_approval_status_fields_are_preserved() {
        let key = key_to_machine(south::KeyPublic {
            key_ref: south::KeyRef {
                backend: south::Token::new("backend-1").unwrap(),
                backend_instance: south::Token::new("instance-2").unwrap(),
                locator: "locator-3".into(),
                key_spec: south::KeySpec::Secp256k1,
                public_key_fingerprint: digest(4),
                derivation: None,
            },
            role: south::KeyRole::WalletRoot,
            canonical_public_key: south::Base64UrlBytes::from_bytes(&[5]),
            addresses: vec!["address-6".into()],
            supported_crypto_suites: vec![south::CryptoSuite::Secp256k1Sha256Recoverable],
            derived_account: None,
        });
        assert_eq!(key.key_ref.backend.as_str(), "backend-1");
        assert_eq!(key.key_ref.backend_instance.as_str(), "instance-2");
        assert_eq!(key.key_ref.locator, "locator-3");
        assert_eq!(key.key_ref.public_key_fingerprint, digest(4));
        assert_eq!(key.role, north::KeyRole::WalletRoot);
        assert_eq!(key.canonical_public_key.decode(), vec![5]);
        assert_eq!(key.addresses, ["address-6"]);
        assert_eq!(
            key.supported_crypto_suites,
            [north::CryptoSuite::Secp256k1Sha256Recoverable]
        );

        let credential = credential_to_machine(south::CredentialPublic {
            credential_id: south::Base64UrlBytes::from_bytes(&[7]),
            wallet_id: south::Token::new("wallet-8").unwrap(),
            created_at_ms: south::DecimalU64::new(9),
            state: south::CredentialState::Revoked,
        });
        assert_eq!(credential.credential_id.decode(), vec![7]);
        assert_eq!(credential.wallet_id.as_str(), "wallet-8");
        assert_eq!(credential.created_at_ms.get(), 9);
        assert_eq!(credential.state, north::CredentialState::Revoked);

        let readiness = readiness_to_machine(south::Readiness {
            service_id: south::Token::new("service-10").unwrap(),
            service_version: "version-11".into(),
            build_digest: digest(12),
            boot_epoch: south::BootEpoch::from_bytes([13; 16]),
            state: south::ReadinessState::DegradedReadOnly,
            conditions: vec![south::Token::new("condition-14").unwrap()],
        });
        assert_eq!(readiness.service_id.as_str(), "service-10");
        assert_eq!(readiness.service_version, "version-11");
        assert_eq!(readiness.build_digest, digest(12));
        assert_eq!(readiness.boot_epoch, north::BootEpoch::from_bytes([13; 16]));
        assert_eq!(readiness.state, north::ReadinessState::DegradedReadOnly);
        assert_eq!(readiness.conditions[0].as_str(), "condition-14");

        let status = approval_status_to_signer(north::ApprovalPublicStatus {
            approval_id: digest(15),
            wallet_id: north::Token::new("wallet-16").unwrap(),
            state: north::ApprovalLifecycleState::Orphaned,
            effective_claim_assurance: Some(north::ClaimAssuranceLevel::InvariantAttested),
            ceremony_url: Some("url-17".into()),
            ceremony_expires_at_ms: Some(north::DecimalU64::new(18)),
        });
        assert_eq!(status.approval_id, digest(15));
        assert_eq!(status.wallet_id.as_str(), "wallet-16");
        assert_eq!(status.state, south::ApprovalLifecycleState::Orphaned);
        assert_eq!(
            status.effective_claim_assurance,
            Some(south::ClaimAssuranceLevel::InvariantAttested)
        );
        assert_eq!(status.ceremony_url.as_deref(), Some("url-17"));
        assert_eq!(status.ceremony_expires_at_ms.unwrap().get(), 18);
    }
}
