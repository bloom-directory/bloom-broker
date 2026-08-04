//! Revocation commands and signed public state projections.

use bloom_broker_api as north;
use bloom_signer_api as south;

pub(crate) fn revoke_request_to_signer(value: north::RevokeRequest) -> south::RevokeRequest {
    south::RevokeRequest {
        operation_id: value.operation_id,
        approval_id: value.approval_id,
        wallet_id: value.wallet_id,
        reason: value.reason,
    }
}

fn approval_tombstone_to_machine(value: south::ApprovalTombstone) -> north::ApprovalTombstone {
    north::ApprovalTombstone {
        approval_id: value.approval_id,
        wallet_id: value.wallet_id,
        wallet_revocation_epoch: value.wallet_revocation_epoch,
        reason: value.reason,
        operation_id: value.operation_id,
        revoked_at_ms: value.revoked_at_ms,
        issuer_service_id: value.issuer_service_id,
        key_id: value.key_id,
        signature: value.signature,
    }
}

fn wallet_tombstone_to_machine(value: south::WalletTombstone) -> north::WalletTombstone {
    north::WalletTombstone {
        wallet_id: value.wallet_id,
        wallet_revocation_epoch: value.wallet_revocation_epoch,
        operation_id: value.operation_id,
        revoked_at_ms: value.revoked_at_ms,
        issuer_service_id: value.issuer_service_id,
        key_id: value.key_id,
        signature: value.signature,
    }
}

pub(crate) fn state_to_machine(value: south::RevocationState) -> north::RevocationState {
    north::RevocationState {
        wallet_id: value.wallet_id,
        wallet_revocation_epoch: value.wallet_revocation_epoch,
        wallet_tombstone: value.wallet_tombstone.map(wallet_tombstone_to_machine),
        approval_tombstone_digest: value.approval_tombstone_digest,
        approval_tombstone_count: value.approval_tombstone_count,
        observed_at_ms: value.observed_at_ms,
        issuer_service_id: value.issuer_service_id,
        key_id: value.key_id,
        signature: value.signature,
    }
}

pub(crate) fn snapshot_to_machine(value: south::RevocationSnapshot) -> north::RevocationSnapshot {
    north::RevocationSnapshot {
        state: state_to_machine(value.state),
        approval_tombstones: value
            .approval_tombstones
            .into_iter()
            .map(approval_tombstone_to_machine)
            .collect(),
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

    #[test]
    fn revocation_state_and_tombstone_authenticators_are_preserved() {
        let state = south::RevocationState {
            wallet_id: south::Token::new("wallet-1").unwrap(),
            wallet_revocation_epoch: south::DecimalU64::new(2),
            wallet_tombstone: Some(south::WalletTombstone {
                wallet_id: south::Token::new("wallet-1").unwrap(),
                wallet_revocation_epoch: south::DecimalU64::new(3),
                operation_id: operation(4),
                revoked_at_ms: south::DecimalU64::new(5),
                issuer_service_id: south::Token::new("issuer-6").unwrap(),
                key_id: south::Token::new("key-7").unwrap(),
                signature: south::Base64UrlBytes::from_bytes(&[8]),
            }),
            approval_tombstone_digest: digest(9),
            approval_tombstone_count: south::DecimalU64::new(10),
            observed_at_ms: south::DecimalU64::new(11),
            issuer_service_id: south::Token::new("issuer-12").unwrap(),
            key_id: south::Token::new("key-13").unwrap(),
            signature: south::Base64UrlBytes::from_bytes(&[14]),
        };
        let mapped = snapshot_to_machine(south::RevocationSnapshot {
            state,
            approval_tombstones: vec![south::ApprovalTombstone {
                approval_id: digest(15),
                wallet_id: south::Token::new("wallet-16").unwrap(),
                wallet_revocation_epoch: south::DecimalU64::new(17),
                reason: "reason-18".into(),
                operation_id: operation(19),
                revoked_at_ms: south::DecimalU64::new(20),
                issuer_service_id: south::Token::new("issuer-21").unwrap(),
                key_id: south::Token::new("key-22").unwrap(),
                signature: south::Base64UrlBytes::from_bytes(&[23]),
            }],
        });
        assert_eq!(mapped.state.wallet_revocation_epoch.get(), 2);
        assert_eq!(mapped.state.approval_tombstone_digest, digest(9));
        assert_eq!(mapped.state.approval_tombstone_count.get(), 10);
        assert_eq!(mapped.state.observed_at_ms.get(), 11);
        assert_eq!(mapped.state.issuer_service_id.as_str(), "issuer-12");
        assert_eq!(mapped.state.key_id.as_str(), "key-13");
        assert_eq!(mapped.state.signature.decode(), vec![14]);
        let wallet = mapped.state.wallet_tombstone.unwrap();
        assert_eq!(wallet.wallet_id.as_str(), "wallet-1");
        assert_eq!(wallet.wallet_revocation_epoch.get(), 3);
        assert_eq!(wallet.operation_id, operation(4));
        assert_eq!(wallet.revoked_at_ms.get(), 5);
        assert_eq!(wallet.issuer_service_id.as_str(), "issuer-6");
        assert_eq!(wallet.key_id.as_str(), "key-7");
        assert_eq!(wallet.signature.decode(), vec![8]);
        let approval = &mapped.approval_tombstones[0];
        assert_eq!(approval.approval_id, digest(15));
        assert_eq!(approval.wallet_id.as_str(), "wallet-16");
        assert_eq!(approval.wallet_revocation_epoch.get(), 17);
        assert_eq!(approval.reason, "reason-18");
        assert_eq!(approval.operation_id, operation(19));
        assert_eq!(approval.revoked_at_ms.get(), 20);
        assert_eq!(approval.issuer_service_id.as_str(), "issuer-21");
        assert_eq!(approval.key_id.as_str(), "key-22");
        assert_eq!(approval.signature.decode(), vec![23]);
    }

    #[test]
    fn revoke_command_identity_is_preserved() {
        let mapped = revoke_request_to_signer(north::RevokeRequest {
            operation_id: operation(24),
            approval_id: digest(25),
            wallet_id: north::Token::new("wallet-26").unwrap(),
            reason: "reason-27".into(),
        });
        assert_eq!(mapped.operation_id, operation(24));
        assert_eq!(mapped.approval_id, digest(25));
        assert_eq!(mapped.wallet_id.as_str(), "wallet-26");
        assert_eq!(mapped.reason, "reason-27");
    }
}
