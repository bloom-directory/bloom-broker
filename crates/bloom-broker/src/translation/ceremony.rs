//! Ceremony enum projections shared only by explicit conversion.

use bloom_broker_api as north;
use bloom_signer_api as south;

pub(crate) fn kind_to_signer(value: north::CeremonyKind) -> south::CeremonyKind {
    match value {
        north::CeremonyKind::SealedApproval => south::CeremonyKind::SealedApproval,
        north::CeremonyKind::WalletRegistration => south::CeremonyKind::WalletRegistration,
        north::CeremonyKind::WalletImport => south::CeremonyKind::WalletImport,
        north::CeremonyKind::WalletExport => south::CeremonyKind::WalletExport,
        north::CeremonyKind::WalletDelete => south::CeremonyKind::WalletDelete,
        north::CeremonyKind::WalletRecovery => south::CeremonyKind::WalletRecovery,
        north::CeremonyKind::CredentialAdd => south::CeremonyKind::CredentialAdd,
        north::CeremonyKind::CredentialReplace => south::CeremonyKind::CredentialReplace,
        north::CeremonyKind::CredentialRemove => south::CeremonyKind::CredentialRemove,
        north::CeremonyKind::BackendEnrollment => south::CeremonyKind::BackendEnrollment,
        north::CeremonyKind::KeyDerive => south::CeremonyKind::KeyDerive,
        north::CeremonyKind::AccountAllocate => south::CeremonyKind::AccountAllocate,
        north::CeremonyKind::AccountRetire => south::CeremonyKind::AccountRetire,
        north::CeremonyKind::PolicyUpdate => south::CeremonyKind::PolicyUpdate,
    }
}

pub(crate) fn kind_to_machine(value: south::CeremonyKind) -> north::CeremonyKind {
    match value {
        south::CeremonyKind::SealedApproval => north::CeremonyKind::SealedApproval,
        south::CeremonyKind::WalletRegistration => north::CeremonyKind::WalletRegistration,
        south::CeremonyKind::WalletImport => north::CeremonyKind::WalletImport,
        south::CeremonyKind::WalletExport => north::CeremonyKind::WalletExport,
        south::CeremonyKind::WalletDelete => north::CeremonyKind::WalletDelete,
        south::CeremonyKind::WalletRecovery => north::CeremonyKind::WalletRecovery,
        south::CeremonyKind::CredentialAdd => north::CeremonyKind::CredentialAdd,
        south::CeremonyKind::CredentialReplace => north::CeremonyKind::CredentialReplace,
        south::CeremonyKind::CredentialRemove => north::CeremonyKind::CredentialRemove,
        south::CeremonyKind::BackendEnrollment => north::CeremonyKind::BackendEnrollment,
        south::CeremonyKind::KeyDerive => north::CeremonyKind::KeyDerive,
        south::CeremonyKind::AccountAllocate => north::CeremonyKind::AccountAllocate,
        south::CeremonyKind::AccountRetire => north::CeremonyKind::AccountRetire,
        south::CeremonyKind::PolicyUpdate => north::CeremonyKind::PolicyUpdate,
    }
}

pub(crate) fn state_to_machine(value: south::CeremonyState) -> north::CeremonyState {
    match value {
        south::CeremonyState::Prepared => north::CeremonyState::Prepared,
        south::CeremonyState::AwaitingUser => north::CeremonyState::AwaitingUser,
        south::CeremonyState::Verifying => north::CeremonyState::Verifying,
        south::CeremonyState::WalletCommitted => north::CeremonyState::WalletCommitted,
        south::CeremonyState::AwaitingRecoveryAck => north::CeremonyState::AwaitingRecoveryAck,
        south::CeremonyState::Completed => north::CeremonyState::Completed,
        south::CeremonyState::ApprovingRootChange => north::CeremonyState::ApprovingRootChange,
        south::CeremonyState::CreatingCredential => north::CeremonyState::CreatingCredential,
        south::CeremonyState::Committing => north::CeremonyState::Committing,
        south::CeremonyState::Succeeded => north::CeremonyState::Succeeded,
        south::CeremonyState::Cancelled => north::CeremonyState::Cancelled,
        south::CeremonyState::Expired => north::CeremonyState::Expired,
        south::CeremonyState::Failed => north::CeremonyState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ceremony_kinds_round_trip() {
        let kinds = [
            north::CeremonyKind::SealedApproval,
            north::CeremonyKind::WalletRegistration,
            north::CeremonyKind::WalletImport,
            north::CeremonyKind::WalletExport,
            north::CeremonyKind::WalletDelete,
            north::CeremonyKind::WalletRecovery,
            north::CeremonyKind::CredentialAdd,
            north::CeremonyKind::CredentialReplace,
            north::CeremonyKind::CredentialRemove,
            north::CeremonyKind::BackendEnrollment,
            north::CeremonyKind::KeyDerive,
            north::CeremonyKind::PolicyUpdate,
        ];
        for kind in kinds {
            assert_eq!(kind_to_machine(kind_to_signer(kind)), kind);
        }
    }
}
