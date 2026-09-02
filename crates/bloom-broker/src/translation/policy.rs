//! Policy custody inputs and deliberate public projections.

use bloom_broker_api as north;
use bloom_signer_api as south;
use sha2::Digest as _;

pub(crate) fn update_to_signer(
    value: north::PolicyUpdateRequest,
) -> Result<south::PolicyUpdateRequest, north::ProtocolError> {
    let policy_bytes = value.proposed_canonical_policy.decode();
    let policy: north::CanonicalWalletPolicy =
        serde_json::from_slice(&policy_bytes).map_err(|error| {
            north::ProtocolError::new(north::ProtocolErrorCode::MalformedFrame, error.to_string())
        })?;
    if serde_jcs::to_vec(&policy).map_err(|error| {
        north::ProtocolError::new(north::ProtocolErrorCode::MalformedFrame, error.to_string())
    })? != policy_bytes
    {
        return Err(north::ProtocolError::new(
            north::ProtocolErrorCode::MalformedFrame,
            "Broker policy bytes are not canonical",
        ));
    }
    let signer_policy = south::CanonicalWalletPolicy {
        wallet_id: policy.wallet_id,
        maximum_approval_lifetime_ms: policy.maximum_approval_lifetime_ms,
        allowed_delegated_authorities: policy.allowed_petal_packages,
        allowed_destinations: policy
            .allowed_destinations
            .into_iter()
            .map(|destination| south::PolicyDestination {
                chain: destination.chain,
                destination: destination.destination,
            })
            .collect(),
        required_verifiers: policy
            .required_verifiers
            .into_iter()
            .map(|required| south::RequiredVerifier {
                verifier_id: required.verifier_id,
                verifier_digest: required.verifier_digest,
            })
            .collect(),
    };
    let signer_policy_bytes = serde_jcs::to_vec(&signer_policy).map_err(|error| {
        north::ProtocolError::new(north::ProtocolErrorCode::MalformedFrame, error.to_string())
    })?;
    let signer_policy_digest =
        north::Digest32::from_bytes(sha2::Sha256::digest(&signer_policy_bytes).into());
    Ok(south::PolicyUpdateRequest {
        operation_id: value.operation_id,
        wallet_id: value.wallet_id,
        baseline_version: value.baseline_version,
        baseline_digest: value.baseline_digest,
        proposed_canonical_policy: south::Base64UrlBytes::from_bytes(&signer_policy_bytes),
        proposed_policy_digest: signer_policy_digest,
        authority_diff_digest: value.authority_diff_digest,
        assurance_level: value.assurance_level,
    })
}

pub(crate) fn snapshot_to_machine(
    value: south::SignedPolicySnapshot,
) -> north::SignedPolicySnapshot {
    north::SignedPolicySnapshot {
        wallet_id: value.wallet_id,
        version: value.version,
        canonical_policy: value.canonical_policy,
        policy_digest: value.policy_digest,
        policy_signing_key_id: value.policy_signing_key_id,
        policy_verifying_key: value.policy_verifying_key,
        signer_signature: value.signer_signature,
    }
}

pub(crate) fn commit_receipt_to_machine(
    value: south::PolicyCommitReceipt,
) -> north::PolicyCommitReceipt {
    north::PolicyCommitReceipt {
        operation_id: value.operation_id,
        wallet_id: value.wallet_id,
        previous_version: value.previous_version,
        committed: snapshot_to_machine(value.committed),
        authority_diff_digest: value.authority_diff_digest,
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

    #[test]
    fn update_snapshot_and_commit_fields_are_preserved() {
        let policy = north::CanonicalWalletPolicy {
            wallet_id: north::Token::new("wallet-2").unwrap(),
            maximum_approval_lifetime_ms: 30_000,
            allowed_petal_packages: vec![digest(5)],
            allowed_destinations: Vec::new(),
            required_verifiers: Vec::new(),
        };
        let policy_bytes = serde_jcs::to_vec(&policy).unwrap();
        let update = north::PolicyUpdateRequest {
            operation_id: north::OperationId::from_bytes([1; 32]),
            wallet_id: north::Token::new("wallet-2").unwrap(),
            baseline_version: north::DecimalU64::new(3),
            baseline_digest: digest(4),
            proposed_canonical_policy: north::Base64UrlBytes::from_bytes(&policy_bytes),
            proposed_policy_digest: north::Digest32::from_bytes(
                sha2::Sha256::digest(&policy_bytes).into(),
            ),
            authority_diff_digest: digest(7),
            assurance_level: north::Token::new("assurance-8").unwrap(),
        };
        let mapped_update = update_to_signer(update).unwrap();
        assert_eq!(
            mapped_update.operation_id,
            north::OperationId::from_bytes([1; 32])
        );
        assert_eq!(mapped_update.wallet_id.as_str(), "wallet-2");
        assert_eq!(mapped_update.baseline_version.get(), 3);
        assert_eq!(mapped_update.baseline_digest, digest(4));
        let mapped_policy: south::CanonicalWalletPolicy =
            serde_json::from_slice(&mapped_update.proposed_canonical_policy.decode()).unwrap();
        assert_eq!(mapped_policy.allowed_delegated_authorities, vec![digest(5)]);
        assert_eq!(
            mapped_update.proposed_policy_digest,
            north::Digest32::from_bytes(
                sha2::Sha256::digest(mapped_update.proposed_canonical_policy.decode()).into(),
            )
        );
        assert_eq!(mapped_update.authority_diff_digest, digest(7));
        assert_eq!(mapped_update.assurance_level.as_str(), "assurance-8");

        let snapshot = south::SignedPolicySnapshot {
            wallet_id: south::Token::new("wallet-9").unwrap(),
            version: south::DecimalU64::new(10),
            canonical_policy: south::Base64UrlBytes::from_bytes(&[11]),
            policy_digest: digest(12),
            policy_signing_key_id: south::Token::new("policy-key-13").unwrap(),
            policy_verifying_key: south::Base64UrlBytes::from_bytes(&[14]),
            signer_signature: south::Base64UrlBytes::from_bytes(&[15]),
        };
        let mapped_snapshot = snapshot_to_machine(snapshot.clone());
        assert_eq!(mapped_snapshot.wallet_id.as_str(), "wallet-9");
        assert_eq!(mapped_snapshot.version.get(), 10);
        assert_eq!(mapped_snapshot.canonical_policy.decode(), vec![11]);
        assert_eq!(mapped_snapshot.policy_digest, digest(12));
        assert_eq!(
            mapped_snapshot.policy_signing_key_id.as_str(),
            "policy-key-13"
        );
        assert_eq!(mapped_snapshot.policy_verifying_key.decode(), vec![14]);
        assert_eq!(mapped_snapshot.signer_signature.decode(), vec![15]);

        let receipt = commit_receipt_to_machine(south::PolicyCommitReceipt {
            operation_id: south::OperationId::from_bytes([16; 32]),
            wallet_id: south::Token::new("wallet-17").unwrap(),
            previous_version: south::DecimalU64::new(18),
            committed: snapshot,
            authority_diff_digest: digest(19),
            signer_key_id: south::Token::new("signer-key-20").unwrap(),
            signer_signature: south::Base64UrlBytes::from_bytes(&[21]),
        });
        assert_eq!(
            receipt.operation_id,
            north::OperationId::from_bytes([16; 32])
        );
        assert_eq!(receipt.wallet_id.as_str(), "wallet-17");
        assert_eq!(receipt.previous_version.get(), 18);
        assert_eq!(receipt.committed.policy_digest, digest(12));
        assert_eq!(receipt.authority_diff_digest, digest(19));
        assert_eq!(receipt.signer_key_id.as_str(), "signer-key-20");
        assert_eq!(receipt.signer_signature.decode(), vec![21]);
    }
}
