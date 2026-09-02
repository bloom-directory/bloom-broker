//! Validated Machine approval terms projected into Signer enforcement terms.

use bloom_broker_api as north;
use bloom_signer_api as south;

use super::{
    delegated,
    key::{crypto_suite_to_signer, key_ref_to_signer},
};

#[derive(Clone, Debug)]
pub(crate) struct PetalAuthorityProjection {
    pub authority_id: north::Digest32,
    pub delegate_id: north::Token,
}

fn subject_to_signer(
    value: north::ApprovalSubject,
    petal: Option<&PetalAuthorityProjection>,
) -> Result<south::ApprovalSubject, north::ProtocolError> {
    Ok(match value {
        north::ApprovalSubject::Petal {
            package_hash,
            route,
            ..
        } => {
            let petal = petal.ok_or_else(|| {
                north::ProtocolError::new(
                    north::ProtocolErrorCode::ProvenanceMismatch,
                    "Petal approval omitted its verified lineage projection",
                )
            })?;
            south::ApprovalSubject::Delegated {
                authority_id: petal.authority_id.clone(),
                active_subject_id: package_hash,
                resource_id: delegated::resource_id(&route)?,
                delegate_id: petal.delegate_id.clone(),
            }
        }
        north::ApprovalSubject::Cli {
            client_id,
            command_class,
        } => south::ApprovalSubject::Cli {
            client_id,
            command_class,
        },
        north::ApprovalSubject::System {
            component_id,
            operation_class,
        } => south::ApprovalSubject::System {
            component_id,
            operation_class,
        },
    })
}

fn assurance_to_signer(value: north::ClaimAssuranceLevel) -> south::ClaimAssuranceLevel {
    match value {
        north::ClaimAssuranceLevel::MachineAsserted => south::ClaimAssuranceLevel::MachineAsserted,
        north::ClaimAssuranceLevel::ProofVerified => south::ClaimAssuranceLevel::ProofVerified,
        north::ClaimAssuranceLevel::InvariantAttested => {
            south::ClaimAssuranceLevel::InvariantAttested
        }
    }
}

fn selector_to_signer(
    value: north::ApprovalSelector,
    petal: Option<&PetalAuthorityProjection>,
) -> Result<south::ApprovalSelector, north::ProtocolError> {
    Ok(match value {
        north::ApprovalSelector::Exact {
            ordered_payload_digests,
            ordered_hashes,
        } => south::ApprovalSelector::Exact {
            ordered_payload_digests,
            ordered_hashes,
        },
        north::ApprovalSelector::Petal {
            package_hash,
            route,
            allowed_operation_classes,
            route_grants,
            required_claim_assurance,
        } => {
            let petal = petal.ok_or_else(|| {
                north::ProtocolError::new(
                    north::ProtocolErrorCode::ProvenanceMismatch,
                    "Petal selector omitted its verified lineage projection",
                )
            })?;
            let resource_id = delegated::resource_id(&route)?;
            let mut resource_grants = route_grants
                .into_iter()
                .map(|grant| {
                    Ok(south::DelegatedResourceGrant {
                        resource_id: delegated::resource_id(&grant.route)?,
                        allowed_operation_classes: grant.allowed_operation_classes,
                        provenance_digest: grant.provenance_digest,
                    })
                })
                .collect::<Result<Vec<_>, north::ProtocolError>>()?;
            resource_grants
                .sort_by(|left, right| left.resource_id.as_str().cmp(right.resource_id.as_str()));
            south::ApprovalSelector::Delegated {
                authority_id: petal.authority_id.clone(),
                active_subject_id: package_hash,
                resource_id,
                allowed_operation_classes,
                resource_grants,
                required_claim_assurance: assurance_to_signer(required_claim_assurance),
            }
        }
    })
}

fn activation_to_signer(value: north::ActivationMode) -> south::ActivationMode {
    match value {
        north::ActivationMode::BootBound => south::ActivationMode::BootBound,
        north::ActivationMode::DurableLocal {
            provider_tier,
            maximum_rearm_until_ms,
        } => south::ActivationMode::DurableLocal {
            provider_tier,
            maximum_rearm_until_ms,
        },
        north::ActivationMode::BackendManaged => south::ActivationMode::BackendManaged,
    }
}

fn limits_to_signer(value: north::ApprovalLimits) -> south::ApprovalLimits {
    south::ApprovalLimits {
        max_operations: value.max_operations,
        max_signatures: value.max_signatures,
        operation_rate_limits: value
            .operation_rate_limits
            .into_iter()
            .map(|window| south::SlidingWindow {
                maximum: window.maximum,
                duration_ms: window.duration_ms,
            })
            .collect(),
        signature_rate_limits: value
            .signature_rate_limits
            .into_iter()
            .map(|window| south::SlidingWindow {
                maximum: window.maximum,
                duration_ms: window.duration_ms,
            })
            .collect(),
        value_limits: value
            .value_limits
            .into_iter()
            .map(|limit| south::ValueLimit {
                asset: south::AssetId {
                    chain: limit.asset.chain,
                    asset: limit.asset.asset,
                },
                lifetime: limit.lifetime,
                rolling_windows: limit
                    .rolling_windows
                    .into_iter()
                    .map(|window| south::ValueWindow {
                        maximum: window.maximum,
                        duration_ms: window.duration_ms,
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// Called only after Broker policy and proposal validation has succeeded.
pub(crate) fn validated_terms_to_signer(
    value: north::SealedApprovalTerms,
    petal: Option<&PetalAuthorityProjection>,
) -> Result<south::SealedApprovalTerms, north::ProtocolError> {
    Ok(south::SealedApprovalTerms {
        subject: subject_to_signer(value.subject, petal)?,
        wallet_id: value.wallet_id,
        key_ref: key_ref_to_signer(value.key_ref),
        allowed_crypto_suites: value
            .allowed_crypto_suites
            .into_iter()
            .map(crypto_suite_to_signer)
            .collect(),
        selector: selector_to_signer(value.selector, petal)?,
        limits: limits_to_signer(value.limits),
        activation_mode: activation_to_signer(value.activation_mode),
        wallet_revocation_epoch: value.wallet_revocation_epoch,
        policy_version: value.policy_version,
        policy_digest: value.policy_digest,
        provenance_digest: value.provenance_digest,
        request_nonce: value.request_nonce,
        issued_at_ms: value.issued_at_ms,
        not_before_ms: value.not_before_ms,
        expires_at_ms: value.expires_at_ms,
        renewal_of: value.renewal_of,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> north::Digest32 {
        north::Digest32::from_bytes([byte; 32])
    }

    #[test]
    fn approval_security_fields_are_preserved() {
        let terms = north::SealedApprovalTerms {
            subject: north::ApprovalSubject::Cli {
                client_id: north::Token::new("cli-1").unwrap(),
                command_class: north::Token::new("sign-2").unwrap(),
            },
            wallet_id: north::Token::new("wallet-3").unwrap(),
            key_ref: north::KeyRef {
                backend: north::Token::new("backend-4").unwrap(),
                backend_instance: north::Token::new("instance-5").unwrap(),
                locator: "locator-6".into(),
                key_spec: north::KeySpec::Secp256k1,
                public_key_fingerprint: digest(7),
                derivation: None,
            },
            allowed_crypto_suites: vec![north::CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: north::ApprovalSelector::Exact {
                ordered_payload_digests: vec![digest(8)],
                ordered_hashes: vec![digest(9)],
            },
            limits: north::ApprovalLimits {
                max_operations: north::DecimalU64::new(1),
                max_signatures: north::DecimalU64::new(1),
                operation_rate_limits: vec![north::SlidingWindow {
                    maximum: north::DecimalU64::new(12),
                    duration_ms: north::DecimalU64::new(13),
                }],
                signature_rate_limits: vec![north::SlidingWindow {
                    maximum: north::DecimalU64::new(14),
                    duration_ms: north::DecimalU64::new(15),
                }],
                value_limits: vec![north::ValueLimit {
                    asset: north::AssetId {
                        chain: north::Token::new("chain-16").unwrap(),
                        asset: "asset-17".into(),
                    },
                    lifetime: north::DecimalU256::parse("18").unwrap(),
                    rolling_windows: vec![north::ValueWindow {
                        maximum: north::DecimalU256::parse("19").unwrap(),
                        duration_ms: north::DecimalU64::new(20),
                    }],
                }],
            },
            activation_mode: north::ActivationMode::DurableLocal {
                provider_tier: north::Token::new("tier-21").unwrap(),
                maximum_rearm_until_ms: north::DecimalU64::new(22),
            },
            wallet_revocation_epoch: north::DecimalU64::new(23),
            policy_version: north::DecimalU64::new(24),
            policy_digest: digest(25),
            provenance_digest: digest(26),
            request_nonce: north::RequestNonce::from_bytes([27; 16]),
            issued_at_ms: north::DecimalU64::new(28),
            not_before_ms: north::DecimalU64::new(29),
            expires_at_ms: north::DecimalU64::new(30),
            renewal_of: Some(digest(31)),
        };
        terms.validate().unwrap();
        let mapped = validated_terms_to_signer(terms, None).unwrap();

        assert!(
            matches!(mapped.subject, south::ApprovalSubject::Cli { ref client_id, ref command_class } if client_id.as_str() == "cli-1" && command_class.as_str() == "sign-2")
        );
        assert_eq!(mapped.wallet_id.as_str(), "wallet-3");
        assert_eq!(mapped.key_ref.backend.as_str(), "backend-4");
        assert_eq!(mapped.key_ref.backend_instance.as_str(), "instance-5");
        assert_eq!(mapped.key_ref.locator, "locator-6");
        assert_eq!(mapped.key_ref.public_key_fingerprint, digest(7));
        assert_eq!(
            mapped.allowed_crypto_suites,
            [south::CryptoSuite::Secp256k1Keccak256Recoverable]
        );
        assert!(
            matches!(mapped.selector, south::ApprovalSelector::Exact { ref ordered_payload_digests, ref ordered_hashes } if ordered_payload_digests == &[digest(8)] && ordered_hashes == &[digest(9)])
        );
        assert_eq!(mapped.limits.max_operations.get(), 1);
        assert_eq!(mapped.limits.max_signatures.get(), 1);
        assert_eq!(mapped.limits.operation_rate_limits[0].maximum.get(), 12);
        assert_eq!(mapped.limits.operation_rate_limits[0].duration_ms.get(), 13);
        assert_eq!(mapped.limits.signature_rate_limits[0].maximum.get(), 14);
        assert_eq!(mapped.limits.signature_rate_limits[0].duration_ms.get(), 15);
        assert_eq!(
            mapped.limits.value_limits[0].asset.chain.as_str(),
            "chain-16"
        );
        assert_eq!(mapped.limits.value_limits[0].asset.asset, "asset-17");
        assert_eq!(mapped.limits.value_limits[0].lifetime.as_str(), "18");
        assert_eq!(
            mapped.limits.value_limits[0].rolling_windows[0]
                .maximum
                .as_str(),
            "19"
        );
        assert_eq!(
            mapped.limits.value_limits[0].rolling_windows[0]
                .duration_ms
                .get(),
            20
        );
        assert!(
            matches!(mapped.activation_mode, south::ActivationMode::DurableLocal { ref provider_tier, ref maximum_rearm_until_ms } if provider_tier.as_str() == "tier-21" && maximum_rearm_until_ms.get() == 22)
        );
        assert_eq!(mapped.wallet_revocation_epoch.get(), 23);
        assert_eq!(mapped.policy_version.get(), 24);
        assert_eq!(mapped.policy_digest, digest(25));
        assert_eq!(mapped.provenance_digest, digest(26));
        assert_eq!(
            mapped.request_nonce,
            north::RequestNonce::from_bytes([27; 16])
        );
        assert_eq!(mapped.issued_at_ms.get(), 28);
        assert_eq!(mapped.not_before_ms.get(), 29);
        assert_eq!(mapped.expires_at_ms.get(), 30);
        assert_eq!(mapped.renewal_of, Some(digest(31)));
    }

    #[test]
    fn invalid_exact_selector_is_rejected_before_translation() {
        let mut terms = {
            let mut value = north::SealedApprovalTerms {
                subject: north::ApprovalSubject::Cli {
                    client_id: north::Token::new("cli").unwrap(),
                    command_class: north::Token::new("sign").unwrap(),
                },
                wallet_id: north::Token::new("wallet").unwrap(),
                key_ref: north::KeyRef {
                    backend: north::Token::new("local").unwrap(),
                    backend_instance: north::Token::new("default").unwrap(),
                    locator: "key".into(),
                    key_spec: north::KeySpec::Secp256k1,
                    public_key_fingerprint: digest(1),
                    derivation: None,
                },
                allowed_crypto_suites: vec![north::CryptoSuite::Secp256k1Keccak256Recoverable],
                selector: north::ApprovalSelector::Exact {
                    ordered_payload_digests: vec![digest(2)],
                    ordered_hashes: vec![digest(3)],
                },
                limits: north::ApprovalLimits {
                    max_operations: north::DecimalU64::new(1),
                    max_signatures: north::DecimalU64::new(1),
                    operation_rate_limits: vec![],
                    signature_rate_limits: vec![],
                    value_limits: vec![],
                },
                activation_mode: north::ActivationMode::BootBound,
                wallet_revocation_epoch: north::DecimalU64::new(0),
                policy_version: north::DecimalU64::new(1),
                policy_digest: digest(4),
                provenance_digest: digest(5),
                request_nonce: north::RequestNonce::from_bytes([6; 16]),
                issued_at_ms: north::DecimalU64::new(10),
                not_before_ms: north::DecimalU64::new(10),
                expires_at_ms: north::DecimalU64::new(20),
                renewal_of: None,
            };
            value.limits.max_signatures = north::DecimalU64::new(2);
            value
        };
        assert_eq!(
            terms.validate().unwrap_err().code,
            north::ProtocolErrorCode::SelectorMismatch
        );
        terms.limits.max_signatures = north::DecimalU64::new(1);
        assert!(terms.validate().is_ok());
    }
}
