//! Signing payloads and checked Signer result projections.

use bloom_broker_api as north;
use bloom_signer_api as south;

use super::key;

pub(crate) fn selector_to_signer(value: &north::ApprovalSelector) -> south::SelectorKind {
    match value {
        north::ApprovalSelector::Exact { .. } => south::SelectorKind::Exact,
        north::ApprovalSelector::Petal { .. } => south::SelectorKind::Petal,
    }
}

pub(crate) fn assurance_to_signer(value: north::ClaimAssurance) -> south::SignerClaimAssurance {
    match value {
        north::ClaimAssurance::MachineAsserted => south::SignerClaimAssurance::MachineAsserted,
        north::ClaimAssurance::ProofVerified {
            verifier_id,
            verifier_digest,
            proof_digest,
        } => south::SignerClaimAssurance::ProofVerified {
            verifier_id,
            verifier_digest,
            proof_digest,
        },
        north::ClaimAssurance::InvariantAttested {
            attestor_id,
            attestation_digest,
        } => south::SignerClaimAssurance::InvariantAttested {
            attestor_id,
            attestation_digest,
        },
    }
}

pub(crate) fn result_to_machine(value: south::SigningResult) -> north::SigningResult {
    north::SigningResult {
        operation_id: value.operation_id,
        operation_digest: value.operation_digest,
        signatures: value
            .signatures
            .into_iter()
            .map(|signature| north::NormalizedSignature {
                crypto_suite: key::crypto_suite_to_machine(signature.crypto_suite),
                bytes: signature.bytes,
            })
            .collect(),
        signer_receipt_digest: value.signer_receipt_digest,
        broker_receipt_digest: value.broker_receipt_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_mapping_is_closed() {
        let exact = north::ApprovalSelector::Exact {
            ordered_payload_digests: vec![],
            ordered_hashes: vec![],
        };
        let petal = north::ApprovalSelector::Petal {
            package_hash: north::Digest32::from_bytes([1; 32]),
            route: "/route".into(),
            allowed_operation_classes: vec![],
            route_grants: Vec::new(),
            required_claim_assurance: north::ClaimAssuranceLevel::MachineAsserted,
        };
        assert_eq!(selector_to_signer(&exact), south::SelectorKind::Exact);
        assert_eq!(selector_to_signer(&petal), south::SelectorKind::Petal);
    }

    #[test]
    fn assurance_security_fields_are_preserved() {
        let proof = assurance_to_signer(north::ClaimAssurance::ProofVerified {
            verifier_id: north::Token::new("verifier-1").unwrap(),
            verifier_digest: north::Digest32::from_bytes([2; 32]),
            proof_digest: north::Digest32::from_bytes([3; 32]),
        });
        assert_eq!(
            proof,
            south::SignerClaimAssurance::ProofVerified {
                verifier_id: south::Token::new("verifier-1").unwrap(),
                verifier_digest: south::Digest32::from_bytes([2; 32]),
                proof_digest: south::Digest32::from_bytes([3; 32]),
            }
        );

        let attested = assurance_to_signer(north::ClaimAssurance::InvariantAttested {
            attestor_id: north::Token::new("attestor-4").unwrap(),
            attestation_digest: north::Digest32::from_bytes([5; 32]),
        });
        assert_eq!(
            attested,
            south::SignerClaimAssurance::InvariantAttested {
                attestor_id: south::Token::new("attestor-4").unwrap(),
                attestation_digest: south::Digest32::from_bytes([5; 32]),
            }
        );
        assert_eq!(
            assurance_to_signer(north::ClaimAssurance::MachineAsserted),
            south::SignerClaimAssurance::MachineAsserted
        );
    }
}
