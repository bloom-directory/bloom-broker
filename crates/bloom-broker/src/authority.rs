use crate::journal::{
    BrokerJournal, BudgetLimits, JournalError, ReservationRequest, SlidingBudgetLimit,
    SlidingValueLimit,
};
use bloom_triad_protocol::{
    ApprovalLifecycleState, ApprovalPublicStatus, ApprovalSelector, ApprovalSubject,
    ApprovalTombstone, Base64UrlBytes, ClaimAssurance, ClaimAssuranceLevel, CryptoSuite,
    CustodyResult, DeclaredFee, Digest32, MachineSignRequest, OperationId,
    PROVENANCE_RECORD_SIGNATURE_DOMAIN, PetalUseClaim, PolicyAuthorityDiff, PolicyUpdateRequest,
    ProtocolErrorCode, RevocationState, SealedApprovalTerms, SignOperationIdentity,
    SignedPolicySnapshot, SignerActivationReceipt, SigningPayloads, Token,
};
pub use bloom_triad_protocol::{CanonicalWalletPolicy, PolicyDestination, RequiredVerifier};
pub use bloom_triad_protocol::{
    ProvenanceFeeAsset as PolicyAsset, ProvenanceOperationClass, ProvenanceRecord,
    ProvenanceSubject, canonical_policy_authority_diff,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use num_bigint::BigUint;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

const POLICY_SIGNATURE_DOMAIN: &[u8] = b"bloom-policy-snapshot/v1";
const CEREMONY_GRANT_DOMAIN: &[u8] = b"bloom-broker-ceremony-grant/v1";
const SIGNER_CEREMONY_RECEIPT_DOMAIN: &[u8] = b"bloom-signer-ceremony-receipt/v1";
const REVOCATION_STATE_DOMAIN: &[u8] = b"bloom-revocation-state/v1";
const APPROVAL_TOMBSTONE_DOMAIN: &[u8] = b"bloom-approval-tombstone/v1";
const WALLET_TOMBSTONE_DOMAIN: &[u8] = b"bloom-wallet-tombstone/v1";

#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("authorization denied ({code}): {message}")]
    Denied { code: &'static str, message: String },
    #[error("authority storage failure: {0}")]
    Storage(String),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

impl From<rusqlite::Error> for AuthorityError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyApprovalGrant {
    pub activation_operation_id: OperationId,
    pub approval_id: Digest32,
    pub approval_digest: Digest32,
    pub review_manifest_digest: Digest32,
    pub replacement_approval_id: Option<Digest32>,
    pub wallet_revocation_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub ceremony_key_id: Token,
    pub ceremony_signature: Base64UrlBytes,
}

#[derive(Clone, Debug)]
pub struct AuthorizationInput {
    pub request: MachineSignRequest,
    pub reserved_at_ms: u64,
    pub observed_utc_ms: Option<u64>,
    pub monotonic_anchor_ns: u64,
    pub clock_boot_epoch: bloom_triad_protocol::BootEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecision {
    pub approval_id: Digest32,
    pub ordered_payload_digests: Vec<Digest32>,
    pub ordered_hashes: Vec<Digest32>,
    pub reserved_values: BTreeMap<String, bloom_triad_protocol::DecimalU256>,
    pub effective_assurance: Option<ClaimAssurance>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochReconciliation {
    Converged,
    AdoptedSignerEpoch,
    PushLocalEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierCapability {
    pub verifier_id: Token,
    pub artifact_digest: Digest32,
    pub assurance: ClaimAssuranceLevel,
    pub established_fields: Vec<Token>,
}

/// Implementations are compiled into Broker and supplied at construction.
/// There is deliberately no path, library name, or runtime loading API.
pub trait AssuranceVerifier: Send + Sync {
    fn capability(&self) -> VerifierCapability;
    fn verify(&self, claim: &PetalUseClaim, evidence: Option<&[u8]>) -> Result<(), String>;
}

#[derive(Default)]
pub struct AssuranceRegistry {
    verifiers: BTreeMap<(String, String), Arc<dyn AssuranceVerifier>>,
}

impl AssuranceRegistry {
    pub fn compiled(verifiers: Vec<Arc<dyn AssuranceVerifier>>) -> Result<Self, AuthorityError> {
        let mut registry = Self::default();
        for verifier in verifiers {
            let capability = verifier.capability();
            let key = (
                capability.verifier_id.as_str().to_owned(),
                capability.artifact_digest.as_str().to_owned(),
            );
            if registry.verifiers.insert(key, verifier).is_some() {
                return Err(denied(
                    "ASSURANCE_REGISTRY_INVALID",
                    "duplicate verifier identity",
                ));
            }
        }
        Ok(registry)
    }

    pub fn capabilities(&self) -> Vec<VerifierCapability> {
        self.verifiers
            .values()
            .map(|verifier| verifier.capability())
            .collect()
    }

    fn verify(
        &self,
        claim: &PetalUseClaim,
        evidence: Option<&[u8]>,
    ) -> Result<Option<VerifierCapability>, AuthorityError> {
        match &claim.claim_assurance {
            ClaimAssurance::MachineAsserted => Ok(None),
            ClaimAssurance::ProofVerified {
                verifier_id,
                verifier_digest,
                ..
            } => {
                let verifier = self
                    .verifiers
                    .get(&(
                        verifier_id.as_str().to_owned(),
                        verifier_digest.as_str().to_owned(),
                    ))
                    .ok_or_else(|| {
                        denied(
                            "ASSURANCE_UNAVAILABLE",
                            "claim names no compiled digest-pinned verifier",
                        )
                    })?;
                if verifier.capability().assurance != ClaimAssuranceLevel::ProofVerified {
                    return Err(denied(
                        "ASSURANCE_MISMATCH",
                        "compiled verifier does not establish proof_verified assurance",
                    ));
                }
                verifier
                    .verify(claim, evidence)
                    .map_err(|message| denied("ASSURANCE_VERIFICATION_FAILED", message))?;
                Ok(Some(verifier.capability()))
            }
            ClaimAssurance::InvariantAttested {
                attestor_id,
                attestation_digest,
            } => {
                let verifier = self
                    .verifiers
                    .get(&(
                        attestor_id.as_str().to_owned(),
                        attestation_digest.as_str().to_owned(),
                    ))
                    .ok_or_else(|| {
                        denied(
                            "ASSURANCE_UNAVAILABLE",
                            "claim names no compiled digest-pinned attestor",
                        )
                    })?;
                if verifier.capability().assurance != ClaimAssuranceLevel::InvariantAttested {
                    return Err(denied(
                        "ASSURANCE_MISMATCH",
                        "compiled verifier does not establish invariant_attested assurance",
                    ));
                }
                verifier
                    .verify(claim, evidence)
                    .map_err(|message| denied("ASSURANCE_VERIFICATION_FAILED", message))?;
                Ok(Some(verifier.capability()))
            }
        }
    }
}

pub struct BrokerAuthority {
    connection: Mutex<Connection>,
    authorization_barrier: Mutex<()>,
    journal: Arc<BrokerJournal>,
    policy_keys: Mutex<BTreeMap<String, (Token, VerifyingKey)>>,
    installer_key_id: Token,
    installer_key: VerifyingKey,
    ceremony_key_id: Token,
    ceremony_key: VerifyingKey,
    revocation_key_id: Token,
    revocation_key: VerifyingKey,
    assurance: AssuranceRegistry,
}

impl BrokerAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        path: impl AsRef<Path>,
        journal: Arc<BrokerJournal>,
        policy_keys: BTreeMap<String, (Token, VerifyingKey)>,
        installer_key_id: Token,
        installer_key: VerifyingKey,
        ceremony_key_id: Token,
        ceremony_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_key: VerifyingKey,
        assurance: AssuranceRegistry,
    ) -> Result<Self, AuthorityError> {
        Self::from_connection(
            Connection::open(path)?,
            journal,
            policy_keys,
            installer_key_id,
            installer_key,
            ceremony_key_id,
            ceremony_key,
            revocation_key_id,
            revocation_key,
            assurance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_in_memory(
        journal: Arc<BrokerJournal>,
        policy_keys: BTreeMap<String, (Token, VerifyingKey)>,
        installer_key_id: Token,
        installer_key: VerifyingKey,
        ceremony_key_id: Token,
        ceremony_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_key: VerifyingKey,
        assurance: AssuranceRegistry,
    ) -> Result<Self, AuthorityError> {
        Self::from_connection(
            Connection::open_in_memory()?,
            journal,
            policy_keys,
            installer_key_id,
            installer_key,
            ceremony_key_id,
            ceremony_key,
            revocation_key_id,
            revocation_key,
            assurance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_connection(
        connection: Connection,
        journal: Arc<BrokerJournal>,
        policy_keys: BTreeMap<String, (Token, VerifyingKey)>,
        installer_key_id: Token,
        installer_key: VerifyingKey,
        ceremony_key_id: Token,
        ceremony_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_key: VerifyingKey,
        assurance: AssuranceRegistry,
    ) -> Result<Self, AuthorityError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS policies (
                wallet_id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                digest TEXT NOT NULL,
                snapshot_jcs TEXT NOT NULL,
                policy_jcs TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wallet_epochs (
                wallet_id TEXT PRIMARY KEY,
                epoch TEXT NOT NULL,
                reconciled INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provenance_catalog (
                subject_jcs TEXT PRIMARY KEY,
                record_digest TEXT NOT NULL,
                record_jcs TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mutation_quota (
                principal TEXT PRIMARY KEY,
                window_started_ms TEXT NOT NULL,
                mutations TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS signer_approval_tombstones (
                approval_id TEXT PRIMARY KEY,
                wallet_id TEXT NOT NULL,
                tombstone_jcs TEXT NOT NULL
            );
            ",
        )?;
        let mut policy_keys = policy_keys;
        {
            let mut statement =
                connection.prepare("SELECT snapshot_jcs FROM policies ORDER BY wallet_id")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                let snapshot: SignedPolicySnapshot =
                    serde_json::from_str(&row?).map_err(storage)?;
                enroll_policy_key_from_snapshot(&snapshot, &mut policy_keys)?;
            }
        }
        Ok(Self {
            connection: Mutex::new(connection),
            authorization_barrier: Mutex::new(()),
            journal,
            policy_keys: Mutex::new(policy_keys),
            installer_key_id,
            installer_key,
            ceremony_key_id,
            ceremony_key,
            revocation_key_id,
            revocation_key,
            assurance,
        })
    }

    pub fn verifier_capabilities(&self) -> Vec<VerifierCapability> {
        self.assurance.capabilities()
    }

    pub fn install_policy(&self, snapshot: &SignedPolicySnapshot) -> Result<(), AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        self.install_policy_locked(snapshot)
    }

    /// Enrolls the per-wallet policy verification key only from the signed
    /// initial snapshot carried by completed wallet registration/import.
    /// Ordinary policy reads cannot call this path.
    pub fn install_initial_policy(
        &self,
        snapshot: &SignedPolicySnapshot,
    ) -> Result<(), AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        if snapshot.version.get() != 1 {
            return Err(denied(
                "POLICY_INVALID",
                "initial wallet custody must install policy version 1",
            ));
        }
        let mut keys = self
            .policy_keys
            .lock()
            .map_err(|_| storage("policy key registry lock poisoned"))?;
        let mut candidate_keys = keys.clone();
        enroll_policy_key_from_snapshot(snapshot, &mut candidate_keys)?;
        let policy = verify_policy_snapshot(snapshot, &candidate_keys)?;
        self.persist_verified_policy(snapshot, &policy)?;
        *keys = candidate_keys;
        Ok(())
    }

    fn install_policy_locked(&self, snapshot: &SignedPolicySnapshot) -> Result<(), AuthorityError> {
        let keys = self
            .policy_keys
            .lock()
            .map_err(|_| storage("policy key registry lock poisoned"))?;
        let policy = verify_policy_snapshot(snapshot, &keys)?;
        drop(keys);
        self.persist_verified_policy(snapshot, &policy)
    }

    fn persist_verified_policy(
        &self,
        snapshot: &SignedPolicySnapshot,
        policy: &CanonicalWalletPolicy,
    ) -> Result<(), AuthorityError> {
        for required in &policy.required_verifiers {
            if !self.assurance.verifiers.contains_key(&(
                required.verifier_id.as_str().to_owned(),
                required.verifier_digest.as_str().to_owned(),
            )) {
                return Err(denied(
                    "POLICY_VERIFIER_UNAVAILABLE",
                    "wallet policy requires a verifier absent from this build",
                ));
            }
        }
        let snapshot_jcs = serde_jcs::to_string(snapshot).map_err(storage)?;
        let policy_jcs = serde_jcs::to_string(&policy).map_err(storage)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let existing: Option<(u64, String)> = transaction
            .query_row(
                "SELECT version, snapshot_jcs FROM policies WHERE wallet_id = ?1",
                [snapshot.wallet_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(version, stored)| {
                version
                    .parse()
                    .map(|version| (version, stored))
                    .map_err(storage)
            })
            .transpose()?;
        if let Some((version, stored)) = existing {
            if snapshot.version.get() == version && snapshot_jcs == stored {
                return Ok(());
            }
            if snapshot.version.get() <= version {
                return Err(denied(
                    "POLICY_ROLLBACK",
                    "policy version must advance monotonically",
                ));
            }
        }
        transaction.execute(
            "INSERT INTO policies(wallet_id, version, digest, snapshot_jcs, policy_jcs)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(wallet_id) DO UPDATE SET
                version=excluded.version, digest=excluded.digest,
                snapshot_jcs=excluded.snapshot_jcs, policy_jcs=excluded.policy_jcs",
            params![
                snapshot.wallet_id.as_str(),
                snapshot.version.get().to_string(),
                snapshot.policy_digest.as_str(),
                snapshot_jcs,
                policy_jcs
            ],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO wallet_epochs(wallet_id, epoch, reconciled)
             VALUES (?1, '0', 1)",
            [snapshot.wallet_id.as_str()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Verifies and adopts a completed Signer custody receipt. The outer
    /// ceremony signature is the trust bridge for an initial policy key; the
    /// policy snapshot's self-signature alone is never sufficient to enroll it.
    pub fn adopt_custody_receipt(&self, receipt: &CustodyResult) -> Result<(), AuthorityError> {
        if receipt.signer_key_id != self.ceremony_key_id
            || Some(receipt.public_status) != receipt.ceremony_kind.successful_terminal_state()
        {
            return Err(denied(
                "CUSTODY_RECEIPT_INVALID",
                "Signer custody receipt key or completion state is invalid",
            ));
        }
        let signature =
            Signature::from_slice(&receipt.signer_signature.decode()).map_err(|_| {
                denied(
                    "CUSTODY_RECEIPT_INVALID",
                    "Signer custody receipt signature is malformed",
                )
            })?;
        self.ceremony_key
            .verify(
                &[
                    SIGNER_CEREMONY_RECEIPT_DOMAIN,
                    receipt
                        .unsigned_canonical_bytes()
                        .map_err(|error| denied("CUSTODY_RECEIPT_INVALID", error.to_string()))?
                        .as_slice(),
                ]
                .concat(),
                &signature,
            )
            .map_err(|_| {
                denied(
                    "CUSTODY_RECEIPT_INVALID",
                    "Signer custody receipt signature is invalid",
                )
            })?;

        if !matches!(
            receipt.ceremony_kind,
            bloom_triad_protocol::CeremonyKind::WalletRegistration
                | bloom_triad_protocol::CeremonyKind::WalletImport
        ) {
            if receipt.initial_policy.is_some() {
                return Err(denied(
                    "CUSTODY_RECEIPT_INVALID",
                    "only wallet registration or import may carry an initial policy",
                ));
            }
            return Ok(());
        }
        let snapshot = receipt.initial_policy.as_ref().ok_or_else(|| {
            denied(
                "CUSTODY_RECEIPT_INVALID",
                "initial wallet custody omitted its initial signed policy",
            )
        })?;
        if receipt.wallet_id.as_ref() != Some(&snapshot.wallet_id) {
            return Err(denied(
                "CUSTODY_RECEIPT_INVALID",
                "registration receipt wallet differs from its initial policy",
            ));
        }
        self.install_initial_policy(snapshot)
    }

    pub fn prepare_approval(
        &self,
        terms: &SealedApprovalTerms,
        review_manifest_digest: &Digest32,
    ) -> Result<Digest32, AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        terms
            .validate()
            .map_err(|error| denied("APPROVAL_INVALID", error.to_string()))?;
        let approval_id = terms
            .approval_id()
            .map_err(|error| denied("APPROVAL_INVALID", error.to_string()))?;
        if let Some(existing) = self.journal.approval_record(&approval_id)? {
            let existing_terms: SealedApprovalTerms =
                serde_json::from_str(&existing.terms_jcs).map_err(storage)?;
            if existing_terms == *terms
                && existing.review_manifest_digest == review_manifest_digest.as_str()
            {
                return Ok(approval_id);
            }
            return Err(denied(
                "OPERATION_ID_CONFLICT",
                "approval identity is already bound to different prepared bytes",
            ));
        }
        if self.is_tombstoned(&approval_id)? {
            return Err(denied(
                "APPROVAL_REVOKED",
                "approval ID is durably tombstoned",
            ));
        }
        let (snapshot, policy) = self.current_policy(&terms.wallet_id)?;
        if terms.policy_version != snapshot.version || terms.policy_digest != snapshot.policy_digest
        {
            return Err(denied(
                "POLICY_SNAPSHOT_MISMATCH",
                "approval is not bound to Broker's verified current policy",
            ));
        }
        if terms
            .expires_at_ms
            .get()
            .saturating_sub(terms.not_before_ms.get())
            > policy.maximum_approval_lifetime_ms
        {
            return Err(denied(
                "POLICY_LIFETIME_EXCEEDED",
                "approval exceeds wallet policy lifetime",
            ));
        }
        let (local_epoch, reconciled) = self.epoch_state(&terms.wallet_id)?;
        if !reconciled || terms.wallet_revocation_epoch.get() != local_epoch {
            return Err(denied(
                "REVOCATION_EPOCH_UNRECONCILED",
                "approval epoch differs from Broker's reconciled wallet epoch",
            ));
        }
        let record = self.catalog_provenance(&subject_for(&terms.subject))?;
        verify_provenance(
            &record,
            &self.installer_key_id,
            &self.installer_key,
            &terms.provenance_digest,
        )?;
        if !provenance_subject_matches(&terms.subject, &record.subject) {
            return Err(denied(
                "PROVENANCE_MISMATCH",
                "provenance subject differs from the approval subject",
            ));
        }
        if let (
            ApprovalSubject::Petal { package_hash, .. },
            ApprovalSelector::Petal {
                allowed_operation_classes,
                ..
            },
        ) = (&terms.subject, &terms.selector)
        {
            if !policy.allowed_petal_packages.contains(package_hash) {
                return Err(denied(
                    "PROVENANCE_MISMATCH",
                    "wallet policy does not permit this Petal package",
                ));
            }
            let declared: BTreeSet<_> = record
                .operation_classes
                .iter()
                .map(|entry| entry.operation_class.as_str())
                .collect();
            if allowed_operation_classes
                .iter()
                .any(|class| !declared.contains(class.as_str()))
            {
                return Err(denied(
                    "PROVENANCE_CLASS_MISMATCH",
                    "approval class is absent from installer-signed provenance",
                ));
            }
        }
        let provenance_jcs = serde_jcs::to_string(&record).map_err(storage)?;
        if let Some(predecessor) = &terms.renewal_of {
            let predecessor_terms = self
                .approval_terms(predecessor)?
                .ok_or_else(|| denied("APPROVAL_NOT_FOUND", "renewal predecessor is missing"))?;
            if predecessor_terms.wallet_id != terms.wallet_id
                || self.journal.approval_state(predecessor)? != Some(ApprovalLifecycleState::Active)
            {
                return Err(denied(
                    "RENEWAL_PREDECESSOR_INVALID",
                    "renewal predecessor must be an active approval for the same wallet",
                ));
            }
        }
        let terms_jcs = serde_jcs::to_string(terms).map_err(storage)?;
        self.journal.create_approval_record(
            &approval_id,
            &terms_jcs,
            review_manifest_digest,
            Some(&provenance_jcs),
            terms.renewal_of.as_ref(),
        )?;
        Ok(approval_id)
    }

    /// Replace the current installer-owned catalog entry for one exact
    /// provenance subject. Machine callers cannot reach this method; the
    /// installer supplies records out of band and Broker verifies them before
    /// making them current.
    pub fn install_provenance(
        &self,
        record: &ProvenanceRecord,
    ) -> Result<Digest32, AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        let digest = Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(record).map_err(storage)?).into(),
        );
        verify_provenance(record, &self.installer_key_id, &self.installer_key, &digest)?;
        let subject_jcs = serde_jcs::to_string(&record.subject).map_err(storage)?;
        let record_jcs = serde_jcs::to_string(record).map_err(storage)?;
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO provenance_catalog(subject_jcs, record_digest, record_jcs)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(subject_jcs) DO UPDATE SET
                record_digest=excluded.record_digest,
                record_jcs=excluded.record_jcs",
            params![subject_jcs, digest.as_str(), record_jcs],
        )?;
        Ok(digest)
    }

    pub fn activate_approval(
        &self,
        grant: &CeremonyApprovalGrant,
        now_ms: u64,
    ) -> Result<(), AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        if grant.ceremony_key_id != self.ceremony_key_id
            || now_ms < grant.issued_at_ms
            || now_ms > grant.expires_at_ms
        {
            return Err(denied(
                "CEREMONY_GRANT_INVALID",
                "ceremony grant key or validity interval is invalid",
            ));
        }
        verify_zeroed_signature(
            grant,
            |unsigned| &mut unsigned.ceremony_signature,
            CEREMONY_GRANT_DOMAIN,
            &self.ceremony_key,
        )?;
        let record = self
            .journal
            .approval_record(&grant.approval_id)?
            .ok_or_else(|| denied("APPROVAL_NOT_FOUND", "approval is not prepared"))?;
        if self.is_tombstoned(&grant.approval_id)? {
            return Err(denied(
                "APPROVAL_REVOKED",
                "tombstoned approval cannot be activated",
            ));
        }
        let terms: SealedApprovalTerms =
            serde_json::from_str(&record.terms_jcs).map_err(storage)?;
        let review_digest = Digest32::new(record.review_manifest_digest)
            .map_err(|error| denied("STORAGE_CORRUPTION", error.to_string()))?;
        let (current_epoch, reconciled) = self.epoch_state(&terms.wallet_id)?;
        if !reconciled || current_epoch != terms.wallet_revocation_epoch.get() {
            return Err(denied(
                "REVOCATION_EPOCH_UNRECONCILED",
                "ceremony cannot activate authority from an old or unreconciled epoch",
            ));
        }
        if grant.approval_digest != grant.approval_id
            || grant.approval_id
                != terms
                    .approval_id()
                    .map_err(|error| denied("APPROVAL_INVALID", error.to_string()))?
            || grant.review_manifest_digest != review_digest
            || grant.replacement_approval_id != terms.renewal_of
            || grant.wallet_revocation_epoch != terms.wallet_revocation_epoch.get()
        {
            return Err(denied(
                "CEREMONY_GRANT_MISMATCH",
                "ceremony grant changed immutable reviewed authority",
            ));
        }
        let grant_jcs = serde_jcs::to_string(grant).map_err(storage)?;
        self.journal.activate_approval_record(
            &grant.approval_id,
            &grant.activation_operation_id,
            &grant_jcs,
        )?;
        Ok(())
    }

    /// Adopt the exact Signer receipt returned by the production ceremony RPC.
    /// This is the process-separated activation path; it verifies the Signer
    /// ceremony key and every immutable prepared field before making Broker
    /// authority active.
    pub fn activate_signer_receipt(
        &self,
        receipt: &SignerActivationReceipt,
        now_ms: u64,
    ) -> Result<(), AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        if receipt.signer_key_id != self.ceremony_key_id
            || now_ms < receipt.activated_at_ms.get()
            || now_ms > receipt.expires_at_ms.get()
        {
            return Err(denied(
                "CEREMONY_GRANT_INVALID",
                "Signer activation receipt key or validity interval is invalid",
            ));
        }
        let signature =
            Signature::from_slice(&receipt.signer_signature.decode()).map_err(|_| {
                denied(
                    "CEREMONY_GRANT_INVALID",
                    "Signer activation receipt signature is malformed",
                )
            })?;
        self.ceremony_key
            .verify(
                &[
                    SIGNER_CEREMONY_RECEIPT_DOMAIN,
                    receipt
                        .unsigned_canonical_bytes()
                        .map_err(|error| denied("CEREMONY_GRANT_INVALID", error.to_string()))?
                        .as_slice(),
                ]
                .concat(),
                &signature,
            )
            .map_err(|_| {
                denied(
                    "CEREMONY_GRANT_INVALID",
                    "Signer activation receipt signature is invalid",
                )
            })?;
        let record = self
            .journal
            .approval_record(&receipt.approval_id)?
            .ok_or_else(|| denied("APPROVAL_NOT_FOUND", "approval is not prepared"))?;
        if self.is_tombstoned(&receipt.approval_id)? {
            return Err(denied(
                "APPROVAL_REVOKED",
                "tombstoned approval cannot be activated",
            ));
        }
        let terms: SealedApprovalTerms =
            serde_json::from_str(&record.terms_jcs).map_err(storage)?;
        let review_digest = Digest32::new(record.review_manifest_digest)
            .map_err(|error| denied("STORAGE_CORRUPTION", error.to_string()))?;
        let (current_epoch, reconciled) = self.epoch_state(&terms.wallet_id)?;
        if !reconciled || current_epoch != terms.wallet_revocation_epoch.get() {
            return Err(denied(
                "REVOCATION_EPOCH_UNRECONCILED",
                "Signer receipt cannot activate authority at an unreconciled epoch",
            ));
        }
        if receipt.approval_digest != receipt.approval_id
            || receipt.approval_id
                != terms
                    .approval_id()
                    .map_err(|error| denied("APPROVAL_INVALID", error.to_string()))?
            || receipt.review_manifest_digest != review_digest
            || receipt.replaced_approval_id != terms.renewal_of
            || receipt.wallet_revocation_epoch != terms.wallet_revocation_epoch
            || receipt.key_ref != terms.key_ref
            || receipt.allowed_crypto_suites != terms.allowed_crypto_suites
            || receipt.activation_mode != terms.activation_mode
            || receipt.expires_at_ms != terms.expires_at_ms
        {
            return Err(denied(
                "CEREMONY_GRANT_MISMATCH",
                "Signer receipt changed immutable reviewed authority",
            ));
        }
        let receipt_jcs = serde_jcs::to_string(receipt).map_err(storage)?;
        self.journal.activate_approval_record(
            &receipt.approval_id,
            &receipt.activation_operation_id,
            &receipt_jcs,
        )?;
        Ok(())
    }

    pub fn approval_terms(
        &self,
        approval_id: &Digest32,
    ) -> Result<Option<SealedApprovalTerms>, AuthorityError> {
        self.journal
            .approval_record(approval_id)?
            .map(|record| serde_json::from_str(&record.terms_jcs).map_err(storage))
            .transpose()
    }

    pub fn approval_public_status(
        &self,
        approval_id: &Digest32,
    ) -> Result<ApprovalPublicStatus, AuthorityError> {
        let terms = self
            .approval_terms(approval_id)?
            .ok_or_else(|| denied("APPROVAL_NOT_FOUND", "approval does not exist"))?;
        let state = self
            .journal
            .approval_state(approval_id)?
            .ok_or_else(|| denied("APPROVAL_NOT_FOUND", "approval state does not exist"))?;
        Ok(ApprovalPublicStatus {
            approval_id: approval_id.clone(),
            wallet_id: terms.wallet_id,
            state,
            effective_claim_assurance: match terms.selector {
                ApprovalSelector::Petal {
                    required_claim_assurance,
                    ..
                } => Some(required_claim_assurance),
                ApprovalSelector::Exact { .. } => None,
            },
            ceremony_url: None,
            ceremony_expires_at_ms: None,
        })
    }

    pub fn approval_public_list(
        &self,
        wallet_id: &Token,
    ) -> Result<Vec<ApprovalPublicStatus>, AuthorityError> {
        self.journal
            .approval_records()?
            .into_iter()
            .filter_map(|(approval_id, record)| {
                match serde_json::from_str::<SealedApprovalTerms>(&record.terms_jcs) {
                    Ok(terms) if &terms.wallet_id == wallet_id => {
                        Some(self.approval_public_status(&approval_id))
                    }
                    Ok(_) => None,
                    Err(error) => Some(Err(storage(error))),
                }
            })
            .collect()
    }

    pub fn policy_snapshot(
        &self,
        wallet_id: &Token,
    ) -> Result<SignedPolicySnapshot, AuthorityError> {
        self.current_policy(wallet_id).map(|(snapshot, _)| snapshot)
    }

    pub fn validate_policy_update(
        &self,
        request: &PolicyUpdateRequest,
    ) -> Result<PolicyAuthorityDiff, AuthorityError> {
        let (baseline, current) = self.current_policy(&request.wallet_id)?;
        if baseline.version != request.baseline_version
            || baseline.policy_digest != request.baseline_digest
        {
            return Err(denied(
                "POLICY_BASELINE_STALE",
                "policy update baseline differs from Broker's verified snapshot",
            ));
        }
        let proposed_bytes = request.proposed_canonical_policy.decode();
        if Digest32::from_bytes(Sha256::digest(&proposed_bytes).into())
            != request.proposed_policy_digest
        {
            return Err(denied(
                "POLICY_INVALID",
                "proposed policy digest does not match its canonical bytes",
            ));
        }
        let proposed: CanonicalWalletPolicy = serde_json::from_slice(&proposed_bytes)
            .map_err(|error| denied("POLICY_INVALID", error.to_string()))?;
        if serde_jcs::to_vec(&proposed).map_err(storage)? != proposed_bytes
            || proposed.wallet_id != request.wallet_id
            || proposed.maximum_approval_lifetime_ms == 0
        {
            return Err(denied(
                "POLICY_INVALID",
                "proposed policy is noncanonical, names another wallet, or has invalid limits",
            ));
        }
        for required in &proposed.required_verifiers {
            if !self.assurance.verifiers.contains_key(&(
                required.verifier_id.as_str().to_owned(),
                required.verifier_digest.as_str().to_owned(),
            )) {
                return Err(denied(
                    "POLICY_VERIFIER_UNAVAILABLE",
                    "proposed policy requires a verifier absent from this build",
                ));
            }
        }
        let authority_diff = canonical_policy_authority_diff(&current, &proposed);
        if authority_diff.digest().map_err(storage)? != request.authority_diff_digest {
            return Err(denied(
                "POLICY_INVALID",
                "authority diff digest does not match Broker-derived policy changes",
            ));
        }
        Ok(authority_diff)
    }

    pub fn wallet_ids(&self) -> Result<Vec<Token>, AuthorityError> {
        let connection = self.lock()?;
        let mut statement =
            connection.prepare("SELECT wallet_id FROM policies ORDER BY wallet_id")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|wallet_id| Token::new(wallet_id).map_err(|error| storage(error.to_string())))
            .collect()
    }

    pub fn revoke_local_approval(&self, approval_id: &Digest32) -> Result<(), AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        self.stop_approval(approval_id)
    }

    pub fn wallet_epoch(&self, wallet_id: &Token) -> Result<u64, AuthorityError> {
        self.local_epoch(wallet_id)
    }

    pub fn authorize(
        &self,
        input: &AuthorizationInput,
    ) -> Result<AuthorizationDecision, AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        let terms = self
            .approval_terms(&input.request.approval_id)?
            .ok_or_else(|| denied("APPROVAL_NOT_FOUND", "approval does not exist"))?;
        if self.is_tombstoned(&input.request.approval_id)? {
            return Err(denied(
                "APPROVAL_REVOKED",
                "tombstoned approval cannot authorize signing",
            ));
        }
        if self.journal.approval_state(&input.request.approval_id)?
            != Some(ApprovalLifecycleState::Active)
        {
            return Err(denied("APPROVAL_INACTIVE", "approval is not active"));
        }
        if input.reserved_at_ms < terms.not_before_ms.get()
            || input.reserved_at_ms > terms.expires_at_ms.get()
        {
            return Err(denied(
                "APPROVAL_OUTSIDE_VALIDITY",
                "approval is not valid at reservation time",
            ));
        }
        if input.request.key_ref != terms.key_ref {
            return Err(denied(
                "KEYREF_MISMATCH",
                "request changed the approved KeyRef",
            ));
        }
        if !terms
            .allowed_crypto_suites
            .contains(&input.request.crypto_suite)
        {
            return Err(denied(
                "SUITE_NOT_ALLOWED",
                "request suite is outside the immutable allowed set",
            ));
        }
        let (snapshot, policy) = self.current_policy(&terms.wallet_id)?;
        if snapshot.version != terms.policy_version || snapshot.policy_digest != terms.policy_digest
        {
            return Err(denied(
                "POLICY_SNAPSHOT_MISMATCH",
                "frozen approval policy no longer matches current verified policy",
            ));
        }
        let (local_epoch, reconciled) = self.epoch_state(&terms.wallet_id)?;
        if !reconciled || local_epoch != terms.wallet_revocation_epoch.get() {
            return Err(denied(
                "APPROVAL_REVOKED",
                "approval predates the current wallet revocation epoch",
            ));
        }
        let payloads = payload_bytes(&input.request.payloads);
        let payload_digests: Vec<_> = payloads
            .iter()
            .map(|payload| Digest32::from_bytes(Sha256::digest(payload).into()))
            .collect();
        let ordered_hashes: Vec<_> = payloads
            .iter()
            .map(|payload| suite_hash(input.request.crypto_suite, payload))
            .collect();
        let current_provenance = self.catalog_provenance(&input.request.provenance)?;
        let frozen_provenance = self.frozen_provenance_for(&terms)?;
        verify_provenance(
            &current_provenance,
            &self.installer_key_id,
            &self.installer_key,
            &terms.provenance_digest,
        )?;
        if current_provenance != frozen_provenance {
            return Err(denied(
                "PROVENANCE_MISMATCH",
                "current installer catalog record differs from the approval-frozen record",
            ));
        }
        if current_provenance.subject != input.request.provenance
            || !provenance_subject_matches(&terms.subject, &current_provenance.subject)
        {
            return Err(denied(
                "PROVENANCE_MISMATCH",
                "current provenance differs from the frozen approval record",
            ));
        }
        let (values, assurance, fee_asset) = match (&terms.selector, &input.request.petal_use_claim)
        {
            (
                ApprovalSelector::Exact {
                    ordered_payload_digests,
                    ordered_hashes: approved_hashes,
                },
                None,
            ) => {
                if ordered_payload_digests != &payload_digests || approved_hashes != &ordered_hashes
                {
                    return Err(denied(
                        "SELECTOR_MISMATCH",
                        "payload bytes, digest, hash, order, count, or algorithm changed",
                    ));
                }
                (BTreeMap::new(), None, None)
            }
            (
                ApprovalSelector::Petal {
                    package_hash,
                    route,
                    allowed_operation_classes,
                    required_claim_assurance,
                },
                Some(claim),
            ) => {
                self.validate_petal_claim(
                    &terms,
                    &policy,
                    input,
                    claim,
                    package_hash,
                    route,
                    allowed_operation_classes,
                    *required_claim_assurance,
                    &payload_digests,
                    &ordered_hashes,
                )?;
                (
                    account_claim_values(&terms, claim, &current_provenance)?,
                    Some(claim.claim_assurance.clone()),
                    declared_fee_asset(claim),
                )
            }
            _ => {
                return Err(denied(
                    "SELECTOR_MISMATCH",
                    "exact requests must omit claims and Petal requests must include one",
                ));
            }
        };
        let claim_digest = input
            .request
            .petal_use_claim
            .as_ref()
            .map(jcs_digest)
            .transpose()?;
        let assurance_digest = input
            .request
            .petal_use_claim
            .as_ref()
            .map(|claim| jcs_digest(&claim.claim_assurance))
            .transpose()?;
        let operation_digest = SignOperationIdentity {
            operation_id: input.request.operation_id.clone(),
            approval_id: input.request.approval_id.clone(),
            key_ref: input.request.key_ref.clone(),
            crypto_suite: input.request.crypto_suite,
            ordered_payload_digests: payload_digests.clone(),
            ordered_hashes: ordered_hashes.clone(),
            petal_use_claim_digest: claim_digest,
            claim_assurance_digest: assurance_digest,
            policy_version: terms.policy_version.clone(),
            policy_digest: terms.policy_digest.clone(),
        }
        .digest()
        .map_err(|error| denied("OPERATION_IDENTITY_INVALID", error.to_string()))?;
        if input.request.operation_digest != operation_digest {
            return Err(denied(
                "OPERATION_ID_CONFLICT",
                "operation digest does not match the authorized payload and claim identity",
            ));
        }
        let reservation = self.journal.reserve(
            &ReservationRequest {
                approval_id: input.request.approval_id.clone(),
                operation_id: input.request.operation_id.clone(),
                operation_digest,
                signature_count: ordered_hashes.len() as u64,
                reserved_at_ms: input.reserved_at_ms,
                observed_utc_ms: input.observed_utc_ms,
                monotonic_anchor_ns: input.monotonic_anchor_ns,
                clock_boot_epoch: input.clock_boot_epoch.clone(),
                values: values.clone(),
            },
            &budget_limits(&terms),
        );
        if let Err(JournalError::Protocol(error)) = &reservation
            && error.code == ProtocolErrorCode::LimitExceededValue
            && fee_asset
                .as_ref()
                .is_some_and(|asset| error.message.contains(asset))
        {
            return Err(denied(
                "FEE_LIMIT_EXCEEDED",
                format!("declared network fee exhausted its native-asset budget: {error}"),
            ));
        }
        reservation?;
        Ok(AuthorizationDecision {
            approval_id: input.request.approval_id.clone(),
            ordered_payload_digests: payload_digests,
            ordered_hashes,
            reserved_values: values,
            effective_assurance: assurance,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_petal_claim(
        &self,
        terms: &SealedApprovalTerms,
        policy: &CanonicalWalletPolicy,
        input: &AuthorizationInput,
        claim: &PetalUseClaim,
        package_hash: &Digest32,
        route: &str,
        allowed_operation_classes: &[Token],
        required_assurance: ClaimAssuranceLevel,
        payload_digests: &[Digest32],
        ordered_hashes: &[Digest32],
    ) -> Result<(), AuthorityError> {
        if &claim.package_hash != package_hash
            || claim.route != route
            || !allowed_operation_classes.contains(&claim.operation_class)
            || claim.crypto_suite != input.request.crypto_suite
            || !terms.allowed_crypto_suites.contains(&claim.crypto_suite)
            || claim.payload_digest != combined_payload_digest(payload_digests)
            || claim.ordered_hashes != ordered_hashes
        {
            return Err(denied(
                "PETAL_CLAIM_MISMATCH",
                "claim package, route, class, suite, payload, hashes, or nonce changed",
            ));
        }
        if assurance_rank(claim.claim_assurance.level()) < assurance_rank(required_assurance) {
            return Err(denied(
                "ASSURANCE_TOO_WEAK",
                "claim assurance is below the approved minimum",
            ));
        }
        if !policy.required_verifiers.is_empty()
            && !policy
                .required_verifiers
                .iter()
                .any(|required| assurance_matches(&claim.claim_assurance, required))
        {
            return Err(denied(
                "POLICY_ASSURANCE_REQUIRED",
                "claim does not use a verifier required by wallet policy",
            ));
        }
        let evidence = input
            .request
            .claim_assurance_evidence
            .as_ref()
            .map(Base64UrlBytes::decode);
        let capability = self.assurance.verify(claim, evidence.as_deref())?;
        if (required_assurance != ClaimAssuranceLevel::MachineAsserted
            || !policy.required_verifiers.is_empty())
            && capability
                .as_ref()
                .is_none_or(|capability| !establishes_authority_fields(capability))
        {
            return Err(denied(
                "ASSURANCE_CONTRACT_INCOMPLETE",
                "verifier contract does not establish every selector and accounting field",
            ));
        }
        let allowed_destinations: BTreeSet<_> =
            policy.allowed_destinations.iter().cloned().collect();
        if claim.declared_destinations.iter().any(|destination| {
            !allowed_destinations.contains(&PolicyDestination {
                chain: destination.chain.clone(),
                destination: destination.destination.clone(),
            })
        }) {
            return Err(denied(
                "DESTINATION_NOT_ALLOWED",
                "claim names a destination outside wallet policy",
            ));
        }
        Ok(())
    }

    pub fn consume_mutation_quota(
        &self,
        principal: &str,
        now_ms: u64,
        window_ms: u64,
        maximum: u64,
    ) -> Result<(), AuthorityError> {
        if window_ms == 0 || maximum == 0 {
            return Err(denied("QUOTA_INVALID", "quota bounds must be positive"));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let current: Option<(u64, u64)> = transaction
            .query_row(
                "SELECT window_started_ms, mutations FROM mutation_quota WHERE principal = ?1",
                [principal],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(start, count)| -> Result<(u64, u64), AuthorityError> {
                Ok((
                    start.parse().map_err(storage)?,
                    count.parse().map_err(storage)?,
                ))
            })
            .transpose()?;
        let (start, next) = match current {
            Some((start, count)) if now_ms.saturating_sub(start) < window_ms => (
                start,
                count
                    .checked_add(1)
                    .ok_or_else(|| denied("MUTATION_QUOTA_EXCEEDED", "mutation quota overflow"))?,
            ),
            _ => (now_ms, 1),
        };
        if next > maximum {
            return Err(denied(
                "MUTATION_QUOTA_EXCEEDED",
                "mutation quota is exhausted; read methods remain available",
            ));
        }
        transaction.execute(
            "INSERT INTO mutation_quota(principal, window_started_ms, mutations)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(principal) DO UPDATE SET
                window_started_ms=excluded.window_started_ms,
                mutations=excluded.mutations",
            params![principal, start.to_string(), next.to_string()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn reconcile_revocation(
        &self,
        state: &RevocationState,
        tombstones: &[ApprovalTombstone],
    ) -> Result<EpochReconciliation, AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        if state.key_id != self.revocation_key_id
            || state.issuer_service_id.as_str() != "bloom-signer"
        {
            return Err(denied(
                "REVOCATION_STATE_INVALID",
                "revocation state uses an untrusted key",
            ));
        }
        verify_zeroed_signature(
            state,
            |unsigned| &mut unsigned.signature,
            REVOCATION_STATE_DOMAIN,
            &self.revocation_key,
        )?;
        if let Some(wallet_tombstone) = &state.wallet_tombstone {
            if wallet_tombstone.wallet_id != state.wallet_id
                || wallet_tombstone.wallet_revocation_epoch != state.wallet_revocation_epoch
                || wallet_tombstone.key_id != self.revocation_key_id
                || wallet_tombstone.issuer_service_id.as_str() != "bloom-signer"
            {
                return Err(denied(
                    "REVOCATION_STATE_INVALID",
                    "wallet tombstone binding differs from revocation state",
                ));
            }
            verify_zeroed_signature(
                wallet_tombstone,
                |unsigned| &mut unsigned.signature,
                WALLET_TOMBSTONE_DOMAIN,
                &self.revocation_key,
            )?;
        }
        let mut sorted = tombstones.to_vec();
        sorted.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
        if sorted
            .windows(2)
            .any(|pair| pair[0].approval_id == pair[1].approval_id)
            || sorted.len() as u64 != state.approval_tombstone_count.get()
            || jcs_digest(&sorted)? != state.approval_tombstone_digest
        {
            return Err(denied(
                "REVOCATION_STATE_INVALID",
                "approval tombstone union does not match signed summary",
            ));
        }
        for tombstone in &sorted {
            if tombstone.wallet_id != state.wallet_id
                || tombstone.wallet_revocation_epoch.get() > state.wallet_revocation_epoch.get()
                || tombstone.key_id != self.revocation_key_id
                || tombstone.issuer_service_id.as_str() != "bloom-signer"
            {
                return Err(denied(
                    "REVOCATION_STATE_INVALID",
                    "approval tombstone binding differs from revocation state",
                ));
            }
            verify_zeroed_signature(
                tombstone,
                |unsigned| &mut unsigned.signature,
                APPROVAL_TOMBSTONE_DOMAIN,
                &self.revocation_key,
            )?;
        }
        self.store_signer_tombstones(&state.wallet_id, &sorted)?;
        for tombstone in &sorted {
            self.stop_approval(&tombstone.approval_id)?;
        }
        let local = self.local_epoch(&state.wallet_id)?;
        let signer = state.wallet_revocation_epoch.get();
        if signer < local {
            let connection = self.lock()?;
            connection.execute(
                "UPDATE wallet_epochs SET reconciled = 0 WHERE wallet_id = ?1",
                [state.wallet_id.as_str()],
            )?;
            return Ok(EpochReconciliation::PushLocalEpoch);
        }
        if signer == local {
            let connection = self.lock()?;
            connection.execute(
                "UPDATE wallet_epochs SET reconciled = 1 WHERE wallet_id = ?1",
                [state.wallet_id.as_str()],
            )?;
            return Ok(EpochReconciliation::Converged);
        }
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO wallet_epochs(wallet_id, epoch, reconciled) VALUES (?1, ?2, 1)
             ON CONFLICT(wallet_id) DO UPDATE SET
                epoch=excluded.epoch, reconciled=excluded.reconciled",
            params![state.wallet_id.as_str(), signer.to_string()],
        )?;
        drop(connection);
        self.revoke_older_approvals(&state.wallet_id, signer)?;
        Ok(EpochReconciliation::AdoptedSignerEpoch)
    }

    fn store_signer_tombstones(
        &self,
        wallet_id: &Token,
        tombstones: &[ApprovalTombstone],
    ) -> Result<(), AuthorityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut statement = transaction.prepare(
            "SELECT approval_id, tombstone_jcs FROM signer_approval_tombstones
             WHERE wallet_id = ?1",
        )?;
        let rows = statement.query_map([wallet_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let incoming: BTreeMap<_, _> = tombstones
            .iter()
            .map(|tombstone| {
                Ok((
                    tombstone.approval_id.as_str().to_owned(),
                    serde_jcs::to_string(tombstone).map_err(storage)?,
                ))
            })
            .collect::<Result<_, AuthorityError>>()?;
        for row in rows {
            let (approval_id, canonical) = row?;
            if incoming.get(&approval_id) != Some(&canonical) {
                return Err(denied(
                    "REVOCATION_STATE_INVALID",
                    "signed tombstone union attempted to delete durable history",
                ));
            }
        }
        drop(statement);
        for tombstone in tombstones {
            let canonical = incoming
                .get(tombstone.approval_id.as_str())
                .expect("incoming map was built from tombstones");
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT tombstone_jcs FROM signer_approval_tombstones
                     WHERE approval_id = ?1",
                    [tombstone.approval_id.as_str()],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.as_ref().is_some_and(|value| value != canonical) {
                return Err(denied(
                    "REVOCATION_STATE_INVALID",
                    "approval tombstone conflicts with durable Broker union",
                ));
            }
            transaction.execute(
                "INSERT OR IGNORE INTO signer_approval_tombstones(
                    approval_id, wallet_id, tombstone_jcs
                 ) VALUES (?1, ?2, ?3)",
                params![
                    tombstone.approval_id.as_str(),
                    wallet_id.as_str(),
                    canonical
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn advance_local_epoch(
        &self,
        wallet_id: &Token,
        expected_epoch: u64,
        next_epoch: u64,
    ) -> Result<(), AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        if next_epoch <= expected_epoch {
            return Err(denied(
                "REVOCATION_EPOCH_ROLLBACK",
                "wallet revocation epoch must increase",
            ));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let current: u64 = transaction
            .query_row(
                "SELECT epoch FROM wallet_epochs WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| denied("POLICY_NOT_FOUND", "wallet epoch is not initialized"))?
            .parse()
            .map_err(storage)?;
        if current != expected_epoch {
            return Err(denied(
                "REVOCATION_EPOCH_STALE",
                "wallet revocation epoch changed concurrently",
            ));
        }
        transaction.execute(
            "UPDATE wallet_epochs SET epoch = ?2, reconciled = 0 WHERE wallet_id = ?1",
            params![wallet_id.as_str(), next_epoch.to_string()],
        )?;
        transaction.commit()?;
        drop(connection);
        self.revoke_older_approvals(wallet_id, next_epoch)
    }

    fn revoke_older_approvals(&self, wallet_id: &Token, epoch: u64) -> Result<(), AuthorityError> {
        let approval_ids: Vec<Digest32> = {
            let mut ids = Vec::new();
            for (id, record) in self.journal.approval_records()? {
                let terms: SealedApprovalTerms =
                    serde_json::from_str(&record.terms_jcs).map_err(storage)?;
                if &terms.wallet_id == wallet_id && terms.wallet_revocation_epoch.get() < epoch {
                    ids.push(id);
                }
            }
            ids
        };
        for approval_id in approval_ids {
            self.stop_approval(&approval_id)?;
        }
        Ok(())
    }

    fn stop_approval(&self, approval_id: &Digest32) -> Result<(), AuthorityError> {
        let next = match self.journal.approval_state(approval_id)? {
            Some(ApprovalLifecycleState::Prepared | ApprovalLifecycleState::AwaitingCeremony) => {
                Some(ApprovalLifecycleState::Failed)
            }
            Some(ApprovalLifecycleState::Orphaned | ApprovalLifecycleState::Active) => {
                Some(ApprovalLifecycleState::Revoked)
            }
            _ => None,
        };
        if let Some(next) = next {
            self.journal.transition_approval(approval_id, next)?;
        }
        Ok(())
    }

    fn current_policy(
        &self,
        wallet_id: &Token,
    ) -> Result<(SignedPolicySnapshot, CanonicalWalletPolicy), AuthorityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT snapshot_jcs, policy_jcs FROM policies WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or_else(|| denied("POLICY_NOT_FOUND", "wallet has no verified policy"))
            .and_then(|(snapshot, policy)| {
                Ok((
                    serde_json::from_str(&snapshot).map_err(storage)?,
                    serde_json::from_str(&policy).map_err(storage)?,
                ))
            })
    }

    fn frozen_provenance_for(
        &self,
        terms: &SealedApprovalTerms,
    ) -> Result<ProvenanceRecord, AuthorityError> {
        let approval_id = terms
            .approval_id()
            .map_err(|error| denied("APPROVAL_INVALID", error.to_string()))?;
        self.journal
            .approval_record(&approval_id)?
            .ok_or_else(|| denied("APPROVAL_NOT_FOUND", "approval has no durable record"))?
            .provenance_jcs
            .ok_or_else(|| denied("PROVENANCE_REQUIRED", "approval has no frozen provenance"))
            .and_then(|value| serde_json::from_str(&value).map_err(storage))
    }

    fn catalog_provenance(
        &self,
        subject: &ProvenanceSubject,
    ) -> Result<ProvenanceRecord, AuthorityError> {
        let subject_jcs = serde_jcs::to_string(subject).map_err(storage)?;
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT record_jcs FROM provenance_catalog WHERE subject_jcs = ?1",
                [subject_jcs],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                denied(
                    "PROVENANCE_REQUIRED",
                    "subject is absent from Broker's installer-owned current catalog",
                )
            })
            .and_then(|value| serde_json::from_str(&value).map_err(storage))
    }

    fn local_epoch(&self, wallet_id: &Token) -> Result<u64, AuthorityError> {
        self.epoch_state(wallet_id).map(|(epoch, _)| epoch)
    }

    fn is_tombstoned(&self, approval_id: &Digest32) -> Result<bool, AuthorityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT 1 FROM signer_approval_tombstones WHERE approval_id = ?1",
                [approval_id.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(Into::into)
    }

    fn epoch_state(&self, wallet_id: &Token) -> Result<(u64, bool), AuthorityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT epoch, reconciled FROM wallet_epochs WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
            .map(|(value, reconciled)| {
                value
                    .parse()
                    .map(|epoch| (epoch, reconciled))
                    .map_err(storage)
            })
            .transpose()
            .map(|value| value.unwrap_or((0, false)))
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, AuthorityError> {
        self.connection
            .lock()
            .map_err(|_| AuthorityError::Storage("authority mutex poisoned".into()))
    }

    fn lock_authorization_barrier(&self) -> Result<MutexGuard<'_, ()>, AuthorityError> {
        self.authorization_barrier
            .lock()
            .map_err(|_| AuthorityError::Storage("authorization barrier poisoned".into()))
    }
}

fn verify_policy_snapshot(
    snapshot: &SignedPolicySnapshot,
    keys: &BTreeMap<String, (Token, VerifyingKey)>,
) -> Result<CanonicalWalletPolicy, AuthorityError> {
    let (key_id, key) = keys
        .get(snapshot.wallet_id.as_str())
        .ok_or_else(|| denied("POLICY_KEY_UNKNOWN", "wallet policy key is not pinned"))?;
    if &snapshot.policy_signing_key_id != key_id {
        return Err(denied(
            "POLICY_KEY_MISMATCH",
            "policy snapshot key ID differs from pinned wallet key",
        ));
    }
    if snapshot.policy_verifying_key.decode() != key.to_bytes() {
        return Err(denied(
            "POLICY_KEY_MISMATCH",
            "policy snapshot public key differs from the pinned wallet key",
        ));
    }
    verify_zeroed_signature(
        snapshot,
        |unsigned| &mut unsigned.signer_signature,
        POLICY_SIGNATURE_DOMAIN,
        key,
    )?;
    let bytes = snapshot.canonical_policy.decode();
    let policy: CanonicalWalletPolicy = serde_json::from_slice(&bytes)
        .map_err(|error| denied("POLICY_INVALID", error.to_string()))?;
    let canonical = serde_jcs::to_vec(&policy).map_err(storage)?;
    if canonical != bytes
        || Digest32::from_bytes(Sha256::digest(&bytes).into()) != snapshot.policy_digest
        || policy.wallet_id != snapshot.wallet_id
        || policy.maximum_approval_lifetime_ms == 0
    {
        return Err(denied(
            "POLICY_INVALID",
            "policy bytes, digest, wallet, or lifetime are invalid",
        ));
    }
    Ok(policy)
}

fn enroll_policy_key_from_snapshot(
    snapshot: &SignedPolicySnapshot,
    keys: &mut BTreeMap<String, (Token, VerifyingKey)>,
) -> Result<(), AuthorityError> {
    let bytes: [u8; 32] = snapshot
        .policy_verifying_key
        .decode()
        .try_into()
        .map_err(|_| {
            denied(
                "POLICY_KEY_MISMATCH",
                "policy verification key must contain 32 bytes",
            )
        })?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| denied("POLICY_KEY_MISMATCH", "policy verification key is invalid"))?;
    if let Some((key_id, pinned)) = keys.get(snapshot.wallet_id.as_str()) {
        if key_id != &snapshot.policy_signing_key_id || pinned != &key {
            return Err(denied(
                "POLICY_KEY_MISMATCH",
                "registration policy key differs from the pinned wallet key",
            ));
        }
    } else {
        keys.insert(
            snapshot.wallet_id.as_str().to_owned(),
            (snapshot.policy_signing_key_id.clone(), key),
        );
    }
    verify_policy_snapshot(snapshot, keys)?;
    Ok(())
}

fn verify_provenance(
    record: &ProvenanceRecord,
    expected_key_id: &Token,
    key: &VerifyingKey,
    expected_digest: &Digest32,
) -> Result<(), AuthorityError> {
    if &record.installer_key_id != expected_key_id {
        return Err(denied(
            "PROVENANCE_KEY_MISMATCH",
            "provenance uses an untrusted installer key",
        ));
    }
    verify_zeroed_signature(
        record,
        |unsigned| &mut unsigned.installer_signature,
        PROVENANCE_RECORD_SIGNATURE_DOMAIN,
        key,
    )?;
    let digest =
        Digest32::from_bytes(Sha256::digest(serde_jcs::to_vec(record).map_err(storage)?).into());
    if &digest != expected_digest {
        return Err(denied(
            "PROVENANCE_MISMATCH",
            "approval provenance digest does not match verified record",
        ));
    }
    let mut classes = BTreeSet::new();
    if matches!(&record.subject, ProvenanceSubject::Petal { route, .. } if route.is_empty())
        || record.operation_classes.is_empty()
        || record
            .operation_classes
            .iter()
            .any(|entry| !classes.insert(entry.operation_class.as_str()))
    {
        return Err(denied(
            "PROVENANCE_INVALID",
            "provenance route/classes are empty or duplicated",
        ));
    }
    Ok(())
}

fn provenance_subject_matches(approval: &ApprovalSubject, provenance: &ProvenanceSubject) -> bool {
    match (approval, provenance) {
        (
            ApprovalSubject::Petal {
                package_hash,
                route,
                ..
            },
            ProvenanceSubject::Petal {
                package_hash: installed_hash,
                route: installed_route,
            },
        ) => package_hash == installed_hash && route == installed_route,
        (
            ApprovalSubject::Cli {
                client_id,
                command_class,
            },
            ProvenanceSubject::Cli {
                client_id: installed_id,
                command_class: installed_class,
            },
        ) => client_id == installed_id && command_class == installed_class,
        (
            ApprovalSubject::System {
                component_id,
                operation_class,
            },
            ProvenanceSubject::System {
                component_id: installed_id,
                operation_class: installed_class,
            },
        ) => component_id == installed_id && operation_class == installed_class,
        _ => false,
    }
}

fn subject_for(approval: &ApprovalSubject) -> ProvenanceSubject {
    match approval {
        ApprovalSubject::Petal {
            package_hash,
            route,
            ..
        } => ProvenanceSubject::Petal {
            package_hash: package_hash.clone(),
            route: route.clone(),
        },
        ApprovalSubject::Cli {
            client_id,
            command_class,
        } => ProvenanceSubject::Cli {
            client_id: client_id.clone(),
            command_class: command_class.clone(),
        },
        ApprovalSubject::System {
            component_id,
            operation_class,
        } => ProvenanceSubject::System {
            component_id: component_id.clone(),
            operation_class: operation_class.clone(),
        },
    }
}

fn verify_zeroed_signature<T: Clone + Serialize>(
    value: &T,
    signature_field: fn(&mut T) -> &mut Base64UrlBytes,
    domain: &[u8],
    key: &VerifyingKey,
) -> Result<(), AuthorityError> {
    let mut unsigned = value.clone();
    let signature_bytes = signature_field(&mut unsigned).decode();
    *signature_field(&mut unsigned) = Base64UrlBytes::from_bytes(&[]);
    let signature: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        denied(
            "SIGNATURE_INVALID",
            "signature must contain exactly 64 bytes",
        )
    })?;
    let mut message = domain.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&unsigned).map_err(storage)?);
    key.verify(&message, &Signature::from_bytes(&signature))
        .map_err(|_| denied("SIGNATURE_INVALID", "signature verification failed"))
}

fn payload_bytes(payloads: &SigningPayloads) -> Vec<Vec<u8>> {
    match payloads {
        SigningPayloads::Single { payload } => vec![payload.decode()],
        SigningPayloads::Batch { children } => {
            children.iter().map(Base64UrlBytes::decode).collect()
        }
    }
}

fn suite_hash(suite: CryptoSuite, payload: &[u8]) -> Digest32 {
    match suite {
        CryptoSuite::Secp256k1Keccak256Recoverable => {
            Digest32::from_bytes(Keccak256::digest(payload).into())
        }
        CryptoSuite::Secp256k1Sha256Recoverable | CryptoSuite::Ed25519Message => {
            Digest32::from_bytes(Sha256::digest(payload).into())
        }
    }
}

fn combined_payload_digest(payload_digests: &[Digest32]) -> Digest32 {
    if payload_digests.len() == 1 {
        return payload_digests[0].clone();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"bloom-batch-payload-digests/v1");
    for digest in payload_digests {
        hasher.update(digest.as_str().as_bytes());
    }
    Digest32::from_bytes(hasher.finalize().into())
}

fn assurance_rank(level: ClaimAssuranceLevel) -> u8 {
    match level {
        ClaimAssuranceLevel::MachineAsserted => 0,
        ClaimAssuranceLevel::ProofVerified => 1,
        ClaimAssuranceLevel::InvariantAttested => 2,
    }
}

fn assurance_matches(assurance: &ClaimAssurance, required: &RequiredVerifier) -> bool {
    match assurance {
        ClaimAssurance::ProofVerified {
            verifier_id,
            verifier_digest,
            ..
        } => verifier_id == &required.verifier_id && verifier_digest == &required.verifier_digest,
        ClaimAssurance::InvariantAttested {
            attestor_id,
            attestation_digest,
        } => {
            attestor_id == &required.verifier_id && attestation_digest == &required.verifier_digest
        }
        ClaimAssurance::MachineAsserted => false,
    }
}

fn establishes_authority_fields(capability: &VerifierCapability) -> bool {
    const REQUIRED: [&str; 10] = [
        "package_hash",
        "route",
        "operation_class",
        "crypto_suite",
        "payload_digest",
        "ordered_hashes",
        "declared_debits",
        "declared_destinations",
        "declared_fee",
        "nonce",
    ];
    REQUIRED.iter().all(|required| {
        capability
            .established_fields
            .iter()
            .any(|field| field.as_str() == *required)
    })
}

fn account_claim_values(
    terms: &SealedApprovalTerms,
    claim: &PetalUseClaim,
    provenance: &ProvenanceRecord,
) -> Result<BTreeMap<String, bloom_triad_protocol::DecimalU256>, AuthorityError> {
    let class = provenance
        .operation_classes
        .iter()
        .find(|entry| entry.operation_class == claim.operation_class)
        .ok_or_else(|| denied("PROVENANCE_CLASS_MISMATCH", "claim class is not catalogued"))?;
    let mut values: BTreeMap<String, BigUint> = BTreeMap::new();
    for debit in &claim.declared_debits {
        add_value(
            &mut values,
            asset_id(debit.asset.chain.as_str(), &debit.asset.asset),
            debit.amount.as_str(),
        )?;
    }
    match (&class.fee_asset, &claim.declared_fee) {
        (None, DeclaredFee::None) => {}
        (
            Some(expected),
            DeclaredFee::Fee {
                chain,
                asset,
                amount,
            },
        ) if &expected.chain == chain && &expected.asset == asset => {
            add_value(
                &mut values,
                asset_id(chain.as_str(), asset),
                amount.as_str(),
            )?;
        }
        (Some(_), DeclaredFee::None) => {
            return Err(denied(
                "FEE_REQUIRED",
                "fee-bearing operation class must declare its native fee",
            ));
        }
        (None, DeclaredFee::Fee { .. }) => {
            return Err(denied(
                "FEE_NOT_ALLOWED",
                "non-fee operation class must declare fee none",
            ));
        }
        _ => {
            return Err(denied(
                "FEE_ASSET_MISMATCH",
                "declared fee does not match provenance fee asset",
            ));
        }
    }
    let allowed: BTreeSet<_> = terms
        .limits
        .value_limits
        .iter()
        .map(|limit| asset_id(limit.asset.chain.as_str(), &limit.asset.asset))
        .collect();
    if values.keys().any(|asset| !allowed.contains(asset)) {
        return Err(denied(
            "VALUE_ASSET_NOT_ALLOWED",
            "declared debit or fee asset is absent from approval limits",
        ));
    }
    values
        .into_iter()
        .map(|(asset, value)| {
            let decimal = bloom_triad_protocol::DecimalU256::parse(value.to_string())
                .map_err(|error| denied("VALUE_OVERFLOW", error.to_string()))?;
            Ok((asset, decimal))
        })
        .collect()
}

fn declared_fee_asset(claim: &PetalUseClaim) -> Option<String> {
    match &claim.declared_fee {
        DeclaredFee::Fee { chain, asset, .. } => Some(asset_id(chain.as_str(), asset)),
        DeclaredFee::None => None,
    }
}

fn jcs_digest(value: &impl Serialize) -> Result<Digest32, AuthorityError> {
    Ok(Digest32::from_bytes(
        Sha256::digest(serde_jcs::to_vec(value).map_err(storage)?).into(),
    ))
}

fn add_value(
    values: &mut BTreeMap<String, BigUint>,
    asset: String,
    amount: &str,
) -> Result<(), AuthorityError> {
    let amount: BigUint = amount.parse().map_err(storage)?;
    let value = values.entry(asset).or_default();
    *value += amount;
    if value.bits() > 256 {
        return Err(denied(
            "VALUE_OVERFLOW",
            "aggregated debit and fee exceed unsigned 256-bit range",
        ));
    }
    Ok(())
}

fn budget_limits(terms: &SealedApprovalTerms) -> BudgetLimits {
    let operation_windows = terms
        .limits
        .operation_rate_limits
        .iter()
        .map(|window| (window.duration_ms.get(), (window.maximum.get(), u64::MAX)));
    let signature_windows = terms
        .limits
        .signature_rate_limits
        .iter()
        .map(|window| (window.duration_ms.get(), (u64::MAX, window.maximum.get())));
    let mut windows: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for (duration, (operations, signatures)) in operation_windows.chain(signature_windows) {
        let entry = windows.entry(duration).or_insert((u64::MAX, u64::MAX));
        entry.0 = entry.0.min(operations);
        entry.1 = entry.1.min(signatures);
    }
    BudgetLimits {
        max_operations: terms.limits.max_operations.get(),
        max_signatures: terms.limits.max_signatures.get(),
        rate_limits: windows
            .into_iter()
            .map(
                |(duration_ms, (max_operations, max_signatures))| SlidingBudgetLimit {
                    max_operations,
                    max_signatures,
                    duration_ms,
                },
            )
            .collect(),
        value_limits: terms
            .limits
            .value_limits
            .iter()
            .map(|limit| {
                (
                    asset_id(limit.asset.chain.as_str(), &limit.asset.asset),
                    limit.lifetime.clone(),
                )
            })
            .collect(),
        rolling_value_limits: terms
            .limits
            .value_limits
            .iter()
            .flat_map(|limit| {
                limit
                    .rolling_windows
                    .iter()
                    .map(|window| SlidingValueLimit {
                        asset_id: asset_id(limit.asset.chain.as_str(), &limit.asset.asset),
                        maximum: window.maximum.clone(),
                        duration_ms: window.duration_ms.get(),
                    })
            })
            .collect(),
    }
}

fn asset_id(chain: &str, asset: &str) -> String {
    format!("{chain}:{asset}")
}

fn denied(code: &'static str, message: impl Into<String>) -> AuthorityError {
    AuthorityError::Denied {
        code,
        message: message.into(),
    }
}

fn storage(error: impl ToString) -> AuthorityError {
    AuthorityError::Storage(error.to_string())
}
