//! Ceremony enum projections shared only by explicit conversion.

use bloom_broker_api as north;
use bloom_signer_api as south;

unit_enum_translation!(CeremonyKind: (pub(crate) kind_to_signer), (pub(crate) kind_to_machine) {
    SealedApproval,
    WalletRegistration,
    WalletImport,
    WalletExport,
    WalletDelete,
    WalletRecovery,
    CredentialAdd,
    CredentialReplace,
    CredentialRemove,
    BackendEnrollment,
    KeyDerive,
    AccountAllocate,
    AccountRetire,
    PolicyUpdate,
});

unit_enum_translation!(CeremonyState: _, (pub(crate) state_to_machine) {
    Prepared,
    AwaitingUser,
    Verifying,
    WalletCommitted,
    AwaitingRecoveryAck,
    Completed,
    ApprovingRootChange,
    CreatingCredential,
    Committing,
    Succeeded,
    Cancelled,
    Expired,
    Failed,
    AlreadyRegistered,
});

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
