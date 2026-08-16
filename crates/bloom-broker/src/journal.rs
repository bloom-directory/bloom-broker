use bloom_audit_checkpoint::CheckpointSink;
use bloom_broker_api::{
    ApprovalLifecycleState, ApprovalLimitState, Base64UrlBytes, BootEpoch, DecimalU64, DecimalU256,
    Digest32, OperationId, OperationState, ProtocolError, ProtocolErrorCode, SealedApprovalTerms,
    SigningResult, Token,
};
use bloom_signer_api::{BrokerValidationReceipt, UnsignedSignRequest};
use bloom_triad_local_transport::{LocalIdentity, sign_journal_head};
use bloom_trusted_time::{DurableClockCondition, PersistedClockState, evaluate_durable_clock};
use num_bigint::BigUint;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

const AUDIT_DOMAIN: &[u8] = b"bloom-broker-audit/v1";
const AUDIT_SIGNATURE_DOMAIN: &[u8] = b"bloom-broker-audit-signature/v1";
const AUDIT_ROTATION_DOMAIN: &[u8] = b"bloom-broker-audit-key-rotation/v1";
const ATTEMPT_BINDING_DOMAIN: &[u8] = b"bloom-broker-attempt-binding/v1";
const BATCH_CHILD_DOMAIN: &[u8] = b"bloom-batch-child/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurablePoint {
    ApprovalTransition,
    OperationReceived,
    OperationTransition,
    ReservationCreated,
    ReservationFinalized,
    BatchPublished,
}

pub trait FaultHook: Send + Sync {
    fn after_durable(&self, point: DurablePoint) -> Result<(), String>;
}

pub trait AuditSigner: Send + Sync {
    fn key_id(&self) -> Token;
    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String>;
    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String>;
}

struct ActiveAuditSigner {
    current: Mutex<Arc<dyn AuditSigner>>,
    trusted: Mutex<Vec<Arc<dyn AuditSigner>>>,
}

impl ActiveAuditSigner {
    fn new(current: Arc<dyn AuditSigner>) -> Self {
        Self {
            current: Mutex::new(current.clone()),
            trusted: Mutex::new(vec![current]),
        }
    }

    fn install(&self, signer: Arc<dyn AuditSigner>) -> Result<(), JournalError> {
        self.trusted
            .lock()
            .map_err(|_| storage("audit signer registry mutex poisoned"))?
            .push(signer.clone());
        *self
            .current
            .lock()
            .map_err(|_| storage("active audit signer mutex poisoned"))? = signer;
        Ok(())
    }
}

impl AuditSigner for ActiveAuditSigner {
    fn key_id(&self) -> Token {
        self.current
            .lock()
            .expect("audit signer mutex poisoned")
            .key_id()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        self.current
            .lock()
            .map_err(|_| "audit signer mutex poisoned".to_owned())?
            .sign(message)
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        self.trusted
            .lock()
            .map_err(|_| "audit signer registry mutex poisoned".to_owned())?
            .iter()
            .find_map(|signer| signer.verify(key_id, message, signature).ok())
            .ok_or_else(|| "unknown or invalid audit signing key".to_owned())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("{0}")]
    Protocol(#[from] ProtocolError),
    #[error("durable transition completed before injected crash at {point:?}: {message}")]
    InjectedCrash {
        point: DurablePoint,
        message: String,
    },
    #[error("journal storage failure: {0}")]
    Storage(String),
}

impl From<bloom_triad_local_transport::TransportError> for JournalError {
    fn from(error: bloom_triad_local_transport::TransportError) -> Self {
        Self::Protocol(error.into())
    }
}

impl From<rusqlite::Error> for JournalError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSnapshot {
    pub operation_id: OperationId,
    pub operation_digest: Digest32,
    pub state: OperationState,
    pub is_batch: bool,
    pub retry_binding_digest: Digest32,
    pub result: Option<SigningResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRecord {
    pub terms_jcs: String,
    pub review_manifest_digest: String,
    pub provenance_jcs: Option<String>,
    pub renewal_of: Option<String>,
    pub activation_operation_id: Option<String>,
    pub ceremony_grant_jcs: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    Reserved,
    Committed,
    Released,
    Quarantined,
}

impl ReservationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "RESERVED",
            Self::Committed => "COMMITTED",
            Self::Released => "RELEASED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationRequest {
    pub approval_id: Digest32,
    pub operation_id: OperationId,
    pub operation_digest: Digest32,
    pub signature_count: u64,
    pub reserved_at_ms: u64,
    pub observed_utc_ms: Option<u64>,
    pub monotonic_anchor_ns: u64,
    pub clock_boot_epoch: BootEpoch,
    pub values: BTreeMap<String, DecimalU256>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetLimits {
    pub max_operations: u64,
    pub max_signatures: u64,
    pub rate_limits: Vec<SlidingBudgetLimit>,
    pub value_limits: BTreeMap<String, DecimalU256>,
    pub rolling_value_limits: Vec<SlidingValueLimit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlidingBudgetLimit {
    pub max_operations: u64,
    pub max_signatures: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlidingValueLimit {
    pub asset_id: String,
    pub maximum: DecimalU256,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeReading {
    pub utc_ms: Option<u64>,
    pub monotonic_elapsed_ms: u64,
    pub monotonic_anchor_ns: u64,
    pub boot_epoch: BootEpoch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockCondition {
    Healthy,
    ForwardJumpRejected,
    Untrusted,
    RollbackFrozen,
    Repaired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockDecision {
    pub effective_now_ms: u64,
    pub condition: ClockCondition,
    pub observed_utc_ms: Option<u64>,
    pub monotonic_anchor_ns: u64,
    pub boot_epoch: BootEpoch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub sequence: u64,
    pub event_type: String,
    pub payload_jcs: String,
    pub previous_hash: Digest32,
    pub entry_hash: Digest32,
    pub signing_key_id: Token,
    pub signature: Base64UrlBytes,
}

pub struct BrokerJournal {
    connection: Arc<Mutex<Connection>>,
    audit_signer: Arc<ActiveAuditSigner>,
    audit_degraded: Arc<AtomicBool>,
    fault_hook: Option<Arc<dyn FaultHook>>,
    self_checkpoint: Arc<Mutex<Option<SelfCheckpoint>>>,
}

#[derive(Clone)]
struct SelfCheckpoint {
    identity: LocalIdentity,
    checkpoints: Arc<dyn CheckpointSink>,
}

impl BrokerJournal {
    pub fn open(
        path: impl AsRef<Path>,
        audit_signer: Arc<dyn AuditSigner>,
    ) -> Result<Self, JournalError> {
        Self::from_connection(Connection::open(path)?, audit_signer)
    }

    pub fn open_in_memory(audit_signer: Arc<dyn AuditSigner>) -> Result<Self, JournalError> {
        Self::from_connection(Connection::open_in_memory()?, audit_signer)
    }

    fn from_connection(
        connection: Connection,
        audit_signer: Arc<dyn AuditSigner>,
    ) -> Result<Self, JournalError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_metadata (
                approval_id TEXT PRIMARY KEY REFERENCES approvals(approval_id),
                terms_jcs TEXT NOT NULL,
                review_manifest_digest TEXT NOT NULL,
                provenance_jcs TEXT,
                renewal_of TEXT REFERENCES approvals(approval_id),
                activation_operation_id TEXT UNIQUE,
                ceremony_grant_jcs TEXT
            );
            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                operation_digest TEXT NOT NULL,
                retry_binding_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                is_batch INTEGER NOT NULL,
                result_jcs TEXT,
                validation_receipt_jcs TEXT
            );
            CREATE TABLE IF NOT EXISTS operation_attempts (
                operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                attempt_id TEXT NOT NULL,
                attempt_digest TEXT NOT NULL,
                PRIMARY KEY (operation_id, attempt_id),
                UNIQUE (operation_id, attempt_digest)
            );
            CREATE TABLE IF NOT EXISTS batch_children (
                parent_operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                child_operation_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                result_jcs TEXT NOT NULL,
                PRIMARY KEY (parent_operation_id, child_operation_id),
                UNIQUE (parent_operation_id, ordinal),
                UNIQUE (child_operation_id)
            );
            CREATE TABLE IF NOT EXISTS reservations (
                approval_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                operation_digest TEXT NOT NULL,
                signature_count TEXT NOT NULL,
                reserved_at_ms TEXT NOT NULL,
                observed_utc_ms TEXT,
                monotonic_anchor_ns TEXT NOT NULL,
                clock_boot_epoch TEXT NOT NULL,
                state TEXT NOT NULL,
                PRIMARY KEY (approval_id, operation_id)
            );
            CREATE TABLE IF NOT EXISTS reservation_values (
                approval_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                amount TEXT NOT NULL,
                PRIMARY KEY (approval_id, operation_id, asset_id),
                FOREIGN KEY (approval_id, operation_id)
                    REFERENCES reservations(approval_id, operation_id)
            );
            CREATE TABLE IF NOT EXISTS audit_chain (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                payload_jcs TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS clock_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_effective_ms TEXT NOT NULL,
                condition TEXT NOT NULL,
                observed_utc_ms TEXT,
                monotonic_anchor_ns TEXT NOT NULL,
                boot_epoch TEXT NOT NULL
            );
            ",
        )?;
        ensure_column(&connection, "reservations", "observed_utc_ms", "TEXT")?;
        ensure_column(
            &connection,
            "reservations",
            "monotonic_anchor_ns",
            "TEXT NOT NULL DEFAULT '0'",
        )?;
        ensure_column(
            &connection,
            "reservations",
            "clock_boot_epoch",
            "TEXT NOT NULL DEFAULT '00000000000000000000000000000000'",
        )?;
        ensure_column(&connection, "clock_state", "observed_utc_ms", "TEXT")?;
        ensure_column(&connection, "operations", "validation_receipt_jcs", "TEXT")?;
        ensure_column(
            &connection,
            "clock_state",
            "monotonic_anchor_ns",
            "TEXT NOT NULL DEFAULT '0'",
        )?;
        ensure_column(
            &connection,
            "clock_state",
            "boot_epoch",
            "TEXT NOT NULL DEFAULT '00000000000000000000000000000000'",
        )?;
        let journal = Self {
            connection: Arc::new(Mutex::new(connection)),
            audit_signer: Arc::new(ActiveAuditSigner::new(audit_signer)),
            audit_degraded: Arc::new(AtomicBool::new(false)),
            fault_hook: None,
            self_checkpoint: Arc::new(Mutex::new(None)),
        };
        if journal.verify_audit_chain().is_err() {
            journal.audit_degraded.store(true, Ordering::SeqCst);
        }
        Ok(journal)
    }

    pub fn with_fault_hook(mut self, fault_hook: Arc<dyn FaultHook>) -> Self {
        self.fault_hook = Some(fault_hook);
        self
    }

    /// Install the independently durable sink for Broker's own authenticated
    /// audit head. Every subsequently appended security event is checkpointed
    /// before its enclosing transaction may report success.
    pub fn install_self_checkpoint(
        &self,
        identity: LocalIdentity,
        checkpoints: Arc<dyn CheckpointSink>,
    ) -> Result<(), JournalError> {
        *self
            .self_checkpoint
            .lock()
            .map_err(|_| storage("Broker self-checkpoint mutex poisoned"))? =
            Some(SelfCheckpoint {
                identity,
                checkpoints,
            });
        Ok(())
    }

    pub fn audit_degraded(&self) -> bool {
        self.audit_degraded.load(Ordering::SeqCst)
    }

    /// Return the current head only after fully verifying the local chain.
    /// `(0, 00..00)` is the explicit empty-chain convention. The externally
    /// reported sequence is the entry count, so DB sequence `N` is exposed as
    /// `N + 1` and the first mutation advances the checkpoint from 0 to 1.
    pub fn verified_audit_head(&self) -> Result<(u64, Digest32), JournalError> {
        let connection = self.lock()?;
        if let Err(error) = verify_audit_chain_connection(&connection, self.audit_signer.as_ref()) {
            self.audit_degraded.store(true, Ordering::SeqCst);
            return Err(error);
        }
        connection
            .query_row(
                "SELECT sequence, entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(sequence, hash)| -> Result<_, JournalError> {
                Ok((
                    u64::try_from(sequence)
                        .map_err(storage)?
                        .checked_add(1)
                        .ok_or_else(|| JournalError::Storage("audit head overflow".into()))?,
                    Digest32::new(hash)?,
                ))
            })
            .transpose()
            .map(|head| {
                head.unwrap_or_else(|| {
                    (
                        0,
                        Digest32::new("00".repeat(32)).expect("fixed zero digest is valid"),
                    )
                })
            })
    }

    /// Latch local security mutations after a required peer/OS checkpoint
    /// cannot be persisted. Read and status methods intentionally remain live.
    pub fn latch_audit_degradation(&self) {
        self.audit_degraded.store(true, Ordering::SeqCst);
    }

    /// Append an old-key-signed transition containing proof of possession of
    /// the replacement key, then atomically select it for subsequent entries.
    /// The supplied signer must remain capable of verifying the historical
    /// key set when used to reopen a rotated journal.
    pub fn rotate_audit_key(&self, replacement: Arc<dyn AuditSigner>) -> Result<(), JournalError> {
        let old_key_id = self.audit_signer.key_id();
        let new_key_id = replacement.key_id();
        if old_key_id == new_key_id {
            return Err(JournalError::Storage(
                "replacement audit key ID must differ".into(),
            ));
        }
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let previous_hash = transaction
            .query_row(
                "SELECT entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| "00".repeat(32));
        let previous_hash = Digest32::new(previous_hash)?;
        let confirmation_message = audit_rotation_message(&old_key_id, &new_key_id, &previous_hash);
        let new_key_confirmation = replacement.sign(&confirmation_message).map_err(storage)?;
        self.append_audit_transaction(
            &transaction,
            "audit.key_rotated",
            &serde_json::json!({
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "prior_head": previous_hash,
                "new_key_confirmation": new_key_confirmation
            }),
            self.audit_signer.as_ref(),
        )?;
        let final_old_head = transaction.query_row(
            "SELECT entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )?;
        let final_old_head = Digest32::new(final_old_head)?;
        self.append_audit_transaction(
            &transaction,
            "audit.key_rotation_completed",
            &serde_json::json!({
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "final_old_head": final_old_head
            }),
            replacement.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        // The committed completion entry is signed by the replacement key, so
        // install it before verifying and checkpointing the committed chain.
        // A checkpoint failure still latches mutations and suppresses success,
        // but the durable rotation remains readable and restart-reconcilable.
        self.audit_signer.install(replacement)?;
        self.checkpoint_committed_head()
    }

    pub fn create_approval(
        &self,
        approval_id: &Digest32,
        state: ApprovalLifecycleState,
    ) -> Result<(), JournalError> {
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO approvals(approval_id, state) VALUES (?1, ?2)",
            params![approval_id.as_str(), approval_state_text(state)?],
        )?;
        self.append_audit_transaction(
            &transaction,
            "approval.created",
            &serde_json::json!({"approval_id": approval_id, "state": state}),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::ApprovalTransition)
    }

    pub fn create_approval_record(
        &self,
        approval_id: &Digest32,
        terms_jcs: &str,
        review_manifest_digest: &Digest32,
        provenance_jcs: Option<&str>,
        renewal_of: Option<&Digest32>,
    ) -> Result<(), JournalError> {
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO approvals(approval_id, state) VALUES (?1, 'AWAITING_CEREMONY')",
            [approval_id.as_str()],
        )?;
        transaction.execute(
            "INSERT INTO approval_metadata(
                approval_id, terms_jcs, review_manifest_digest, provenance_jcs, renewal_of
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                approval_id.as_str(),
                terms_jcs,
                review_manifest_digest.as_str(),
                provenance_jcs,
                renewal_of.map(Digest32::as_str)
            ],
        )?;
        self.append_audit_transaction(
            &transaction,
            "approval.prepared",
            &serde_json::json!({
                "approval_id": approval_id,
                "state": ApprovalLifecycleState::AwaitingCeremony,
                "review_manifest_digest": review_manifest_digest
            }),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::ApprovalTransition)
    }

    pub fn approval_record(
        &self,
        approval_id: &Digest32,
    ) -> Result<Option<ApprovalRecord>, JournalError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT terms_jcs, review_manifest_digest, provenance_jcs, renewal_of,
                        activation_operation_id, ceremony_grant_jcs
                 FROM approval_metadata WHERE approval_id = ?1",
                [approval_id.as_str()],
                |row| {
                    Ok(ApprovalRecord {
                        terms_jcs: row.get(0)?,
                        review_manifest_digest: row.get(1)?,
                        provenance_jcs: row.get(2)?,
                        renewal_of: row.get(3)?,
                        activation_operation_id: row.get(4)?,
                        ceremony_grant_jcs: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn approval_records(&self) -> Result<Vec<(Digest32, ApprovalRecord)>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT approval_id, terms_jcs, review_manifest_digest, provenance_jcs, renewal_of,
                    activation_operation_id, ceremony_grant_jcs
             FROM approval_metadata ORDER BY approval_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                ApprovalRecord {
                    terms_jcs: row.get(1)?,
                    review_manifest_digest: row.get(2)?,
                    provenance_jcs: row.get(3)?,
                    renewal_of: row.get(4)?,
                    activation_operation_id: row.get(5)?,
                    ceremony_grant_jcs: row.get(6)?,
                },
            ))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (approval_id, record) = row?;
            records.push((
                Digest32::new(approval_id).map_err(|error| JournalError::Protocol(error.into()))?,
                record,
            ));
        }
        Ok(records)
    }

    pub fn activate_approval_record(
        &self,
        approval_id: &Digest32,
        activation_operation_id: &OperationId,
        ceremony_grant_jcs: &str,
    ) -> Result<(), JournalError> {
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let (state, existing_operation, renewal_of): (String, Option<String>, Option<String>) =
            transaction
                .query_row(
                    "SELECT approvals.state, approval_metadata.activation_operation_id,
                        approval_metadata.renewal_of
                 FROM approvals JOIN approval_metadata USING (approval_id)
                 WHERE approval_id = ?1",
                    [approval_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?
                .ok_or_else(|| {
                    protocol(ProtocolErrorCode::ApprovalNotFound, "approval not found")
                })?;
        if let Some(existing_operation) = existing_operation {
            if existing_operation == activation_operation_id.as_str()
                && parse_approval_state(&state)? == ApprovalLifecycleState::Active
            {
                transaction.commit()?;
                drop(connection);
                self.checkpoint_committed_head()?;
                return Ok(());
            }
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "approval ceremony activation was replayed with conflicting authority",
            )
            .into());
        }
        if parse_approval_state(&state)? != ApprovalLifecycleState::AwaitingCeremony {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "approval is not awaiting ceremony activation",
            )
            .into());
        }
        if let Some(replacement) = &renewal_of {
            let replacement_state: String = transaction
                .query_row(
                    "SELECT state FROM approvals WHERE approval_id = ?1",
                    [replacement],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or_else(|| {
                    protocol(
                        ProtocolErrorCode::ApprovalNotFound,
                        "renewal predecessor is missing",
                    )
                })?;
            if parse_approval_state(&replacement_state)? != ApprovalLifecycleState::Active {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "renewal predecessor is no longer active",
                )
                .into());
            }
            transaction.execute(
                "UPDATE approvals SET state = 'REVOKED' WHERE approval_id = ?1",
                [replacement],
            )?;
        }
        transaction.execute(
            "UPDATE approval_metadata
             SET activation_operation_id = ?2, ceremony_grant_jcs = ?3
             WHERE approval_id = ?1",
            params![
                approval_id.as_str(),
                activation_operation_id.as_str(),
                ceremony_grant_jcs
            ],
        )?;
        transaction.execute(
            "UPDATE approvals SET state = 'ACTIVE' WHERE approval_id = ?1",
            [approval_id.as_str()],
        )?;
        let signer_receipt_digest =
            Digest32::from_bytes(Sha256::digest(ceremony_grant_jcs.as_bytes()).into());
        let signer_receipt: serde_json::Value =
            serde_json::from_str(ceremony_grant_jcs).map_err(storage)?;
        self.append_audit_transaction(
            &transaction,
            "approval.transition",
            &serde_json::json!({
                "approval_id": approval_id,
                "from": ApprovalLifecycleState::AwaitingCeremony,
                "to": ApprovalLifecycleState::Active,
                "activation_operation_id": activation_operation_id,
                "renewal_of": renewal_of,
                "correlation_schema": "v1",
                "signer_activation_receipt_digest": signer_receipt_digest,
                "ceremony_id": signer_receipt.get("ceremony_id"),
                "review_manifest_digest": signer_receipt.get("review_manifest_digest"),
                "signer_key_id": signer_receipt.get("signer_key_id")
            }),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::ApprovalTransition)
    }

    pub fn transition_approval(
        &self,
        approval_id: &Digest32,
        next: ApprovalLifecycleState,
    ) -> Result<(), JournalError> {
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let current_text: String = transaction
            .query_row(
                "SELECT state FROM approvals WHERE approval_id = ?1",
                [approval_id.as_str()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| protocol(ProtocolErrorCode::ApprovalNotFound, "approval not found"))?;
        let current = parse_approval_state(&current_text)?;
        if !valid_approval_transition(current, next) {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                format!(
                    "invalid approval transition {current_text} -> {}",
                    approval_state_text(next)?
                ),
            )
            .into());
        }
        transaction.execute(
            "UPDATE approvals SET state = ?2 WHERE approval_id = ?1",
            params![approval_id.as_str(), approval_state_text(next)?],
        )?;
        self.append_audit_transaction(
            &transaction,
            "approval.transition",
            &serde_json::json!({"approval_id": approval_id, "from": current, "to": next}),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::ApprovalTransition)
    }

    pub fn approval_state(
        &self,
        approval_id: &Digest32,
    ) -> Result<Option<ApprovalLifecycleState>, JournalError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT state FROM approvals WHERE approval_id = ?1",
                [approval_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|state| parse_approval_state(&state))
            .transpose()
    }

    pub fn approval_limit_state(
        &self,
        approval_id: &Digest32,
    ) -> Result<ApprovalLimitState, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT state, signature_count FROM reservations WHERE approval_id = ?1")?;
        let rows = statement.query_map([approval_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut committed_operations = 0_u64;
        let mut reserved_operations = 0_u64;
        let mut quarantined_operations = 0_u64;
        let mut committed_signatures = 0_u64;
        let mut reserved_signatures = 0_u64;
        let mut quarantined_signatures = 0_u64;
        for row in rows {
            let (state, signatures) = row?;
            let signatures = signatures.parse::<u64>().map_err(storage)?;
            match state.as_str() {
                "COMMITTED" => {
                    committed_operations += 1;
                    committed_signatures = committed_signatures.saturating_add(signatures);
                }
                "RESERVED" => {
                    reserved_operations += 1;
                    reserved_signatures = reserved_signatures.saturating_add(signatures);
                }
                "QUARANTINED" => {
                    quarantined_operations += 1;
                    quarantined_signatures = quarantined_signatures.saturating_add(signatures);
                }
                "RELEASED" => {}
                _ => {
                    return Err(JournalError::Storage(
                        "reservation contains an unknown state".into(),
                    ));
                }
            }
        }
        Ok(ApprovalLimitState {
            approval_id: approval_id.clone(),
            committed_operations: DecimalU64::new(committed_operations),
            reserved_operations: DecimalU64::new(reserved_operations),
            quarantined_operations: DecimalU64::new(quarantined_operations),
            committed_signatures: DecimalU64::new(committed_signatures),
            reserved_signatures: DecimalU64::new(reserved_signatures),
            quarantined_signatures: DecimalU64::new(quarantined_signatures),
        })
    }

    pub fn begin_sign_attempt(
        &self,
        request: &UnsignedSignRequest,
        is_batch: bool,
        validation_receipt: &BrokerValidationReceipt,
    ) -> Result<OperationSnapshot, JournalError> {
        if request.operation_digest
            != request
                .operation_identity()
                .digest()
                .map_err(signer_protocol)?
            || request.attempt_digest
                != request.computed_attempt_digest().map_err(signer_protocol)?
            || request.validation_receipt_digest
                != validation_receipt.digest().map_err(signer_protocol)?
            || validation_receipt.approval_id != request.approval_id
            || validation_receipt.operation_digest != request.operation_digest
            || validation_receipt.policy_version != request.policy_version
            || validation_receipt.policy_digest != request.policy_digest
            || validation_receipt.claim_digest != request.petal_use_claim_digest
            || validation_receipt.assurance_digest != request.claim_assurance_digest
            || validation_receipt.broker_key_id != request.broker_signing_key_id
            || validation_receipt.broker_signature.decode().len() != 64
        {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "operation or attempt digest does not match its canonical preimage",
            )
            .into());
        }
        let retry_binding_digest = attempt_retry_binding_digest(request)?;
        let validation_receipt_jcs = jcs_string(validation_receipt)?;
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let existing = read_operation(&transaction, &request.operation_id)?;
        let snapshot = if let Some(existing) = existing {
            if existing.operation_digest != request.operation_digest {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "operation ID was reused with a different stable digest",
                )
                .into());
            }
            if existing.is_batch != is_batch {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "operation ID changed between single and batch semantics",
                )
                .into());
            }
            if existing.retry_binding_digest != retry_binding_digest {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "retry changed a field outside the permitted attempt envelope",
                )
                .into());
            }
            let retained: String = transaction.query_row(
                "SELECT validation_receipt_jcs FROM operations WHERE operation_id=?1",
                [request.operation_id.as_str()],
                |row| row.get(0),
            )?;
            if retained != validation_receipt_jcs {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "retry changed the signed Broker validation receipt",
                )
                .into());
            }
            existing
        } else {
            transaction.execute(
                "INSERT INTO operations(
                    operation_id, operation_digest, retry_binding_digest, state, is_batch,
                    validation_receipt_jcs
                 ) VALUES (?1, ?2, ?3, 'RECEIVED', ?4, ?5)",
                params![
                    request.operation_id.as_str(),
                    request.operation_digest.as_str(),
                    retry_binding_digest.as_str(),
                    is_batch,
                    validation_receipt_jcs
                ],
            )?;
            self.append_audit_transaction(
                &transaction,
                "operation.received",
                &serde_json::json!({
                    "correlation_schema": "v1",
                    "operation_id": request.operation_id,
                    "operation_digest": request.operation_digest,
                    "validation_receipt_digest": request.validation_receipt_digest,
                    "is_batch": is_batch
                }),
                self.audit_signer.as_ref(),
            )?;
            OperationSnapshot {
                operation_id: request.operation_id.clone(),
                operation_digest: request.operation_digest.clone(),
                state: OperationState::Received,
                is_batch,
                retry_binding_digest,
                result: None,
            }
        };
        let prior_attempt: Option<String> = transaction
            .query_row(
                "SELECT attempt_digest FROM operation_attempts
                 WHERE operation_id = ?1 AND attempt_id = ?2",
                params![request.operation_id.as_str(), request.attempt_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if prior_attempt
            .as_deref()
            .is_some_and(|digest| digest != request.attempt_digest.as_str())
        {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "attempt ID was reused with a different attempt digest",
            )
            .into());
        }
        transaction.execute(
            "INSERT OR IGNORE INTO operation_attempts(operation_id, attempt_id, attempt_digest)
             VALUES (?1, ?2, ?3)",
            params![
                request.operation_id.as_str(),
                request.attempt_id.as_str(),
                request.attempt_digest.as_str()
            ],
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::OperationReceived)?;
        Ok(snapshot)
    }

    pub fn operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<OperationSnapshot>, JournalError> {
        let connection = self.lock()?;
        read_operation(&connection, operation_id)
    }

    pub fn validation_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<BrokerValidationReceipt>, JournalError> {
        self.lock()?
            .query_row(
                "SELECT validation_receipt_jcs FROM operations WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .map(|canonical| serde_json::from_str(&canonical).map_err(storage))
            .transpose()
    }

    pub fn transition_operation(
        &self,
        operation_id: &OperationId,
        next: OperationState,
    ) -> Result<(), JournalError> {
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let current = read_operation(&transaction, operation_id)?
            .ok_or_else(|| protocol(ProtocolErrorCode::ApprovalNotFound, "operation not found"))?;
        if current.result.is_some() || !valid_operation_transition(current.state, next) {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "invalid or post-publication operation transition",
            )
            .into());
        }
        transaction.execute(
            "UPDATE operations SET state = ?2 WHERE operation_id = ?1",
            params![operation_id.as_str(), operation_state_text(next)?],
        )?;
        self.append_audit_transaction(
            &transaction,
            "operation.transition",
            &serde_json::json!({"operation_id": operation_id, "from": current.state, "to": next}),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::OperationTransition)
    }

    pub fn reserve(
        &self,
        request: &ReservationRequest,
        limits: &BudgetLimits,
    ) -> Result<(), JournalError> {
        self.reserve_for_clock_profile(request, limits, true)
    }

    pub fn reserve_for_clock_profile(
        &self,
        request: &ReservationRequest,
        limits: &BudgetLimits,
        durable_clock_guard: bool,
    ) -> Result<(), JournalError> {
        if request.signature_count == 0 {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "reservation signature count must be positive",
            )
            .into());
        }
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let approval_state: Option<String> = transaction
            .query_row(
                "SELECT approvals.state
                 FROM approvals JOIN approval_metadata USING (approval_id)
                 WHERE approvals.approval_id = ?1",
                [request.approval_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if approval_state.as_deref() != Some("ACTIVE") {
            return Err(protocol(
                ProtocolErrorCode::ApprovalRevoked,
                "reservation requires an active canonical approval",
            )
            .into());
        }
        if durable_clock_guard {
            validate_reservation_clock(
                &transaction,
                request.reserved_at_ms,
                !limits.rate_limits.is_empty() || !limits.rolling_value_limits.is_empty(),
            )?;
        }
        if let Some(existing) = reservation_state(&transaction, request)? {
            if existing == ReservationState::Reserved {
                if reservation_matches(&transaction, request)? {
                    transaction.commit()?;
                    drop(connection);
                    self.checkpoint_committed_head()?;
                    return Ok(());
                }
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "same reservation operation changed immutable accounting",
                )
                .into());
            }
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "reservation operation is already finalized",
            )
            .into());
        }
        let operations: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM reservations
             WHERE approval_id = ?1 AND state != 'RELEASED'",
            [request.approval_id.as_str()],
            |row| row.get(0),
        )?;
        let operations = u64::try_from(operations).map_err(storage)?;
        let mut signatures = 0_u64;
        {
            let mut statement = transaction.prepare(
                "SELECT signature_count FROM reservations
                 WHERE approval_id = ?1 AND state != 'RELEASED'",
            )?;
            let rows = statement.query_map([request.approval_id.as_str()], |row| {
                row.get::<_, String>(0)
            })?;
            for row in rows {
                signatures = signatures
                    .checked_add(row?.parse::<u64>().map_err(storage)?)
                    .ok_or_else(|| {
                        protocol(
                            ProtocolErrorCode::LimitExceededSignatures,
                            "signature counter overflow",
                        )
                    })?;
            }
        }
        if operations
            .checked_add(1)
            .is_none_or(|value| value > limits.max_operations)
        {
            return Err(protocol(
                ProtocolErrorCode::LimitExceededOperations,
                "operation lifetime limit exceeded",
            )
            .into());
        }
        if signatures
            .checked_add(request.signature_count)
            .is_none_or(|value| value > limits.max_signatures)
        {
            return Err(protocol(
                ProtocolErrorCode::LimitExceededSignatures,
                "signature lifetime limit exceeded",
            )
            .into());
        }
        validate_rate_limits(&transaction, request, limits)?;
        validate_value_limits(&transaction, request, limits)?;
        validate_rolling_value_limits(&transaction, request, limits)?;
        transaction.execute(
            "INSERT INTO reservations(
                approval_id, operation_id, operation_digest,
                signature_count, reserved_at_ms, observed_utc_ms,
                monotonic_anchor_ns, clock_boot_epoch, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'RESERVED')",
            params![
                request.approval_id.as_str(),
                request.operation_id.as_str(),
                request.operation_digest.as_str(),
                request.signature_count.to_string(),
                request.reserved_at_ms.to_string(),
                request.observed_utc_ms.map(|value| value.to_string()),
                request.monotonic_anchor_ns.to_string(),
                request.clock_boot_epoch.as_str(),
            ],
        )?;
        for (asset_id, amount) in &request.values {
            transaction.execute(
                "INSERT INTO reservation_values(approval_id, operation_id, asset_id, amount)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    request.approval_id.as_str(),
                    request.operation_id.as_str(),
                    asset_id,
                    amount.as_str()
                ],
            )?;
        }
        self.append_audit_transaction(
            &transaction,
            "reservation.created",
            &serde_json::json!({
                "approval_id": request.approval_id,
                "operation_id": request.operation_id,
                "operation_digest": request.operation_digest,
                "signature_count": request.signature_count,
                "values": request.values
            }),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::ReservationCreated)
    }

    pub fn finalize_reservation(
        &self,
        approval_id: &Digest32,
        operation_id: &OperationId,
        next: ReservationState,
    ) -> Result<(), JournalError> {
        if next == ReservationState::Reserved {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "reservation finalization requires a terminal ledger state",
            )
            .into());
        }
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let current: Option<String> = transaction
            .query_row(
                "SELECT state FROM reservations
                 WHERE approval_id = ?1 AND operation_id = ?2",
                params![approval_id.as_str(), operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        match current.as_deref() {
            Some("RESERVED") => {}
            Some(value) if value == next.as_str() => {
                transaction.commit()?;
                drop(connection);
                self.checkpoint_committed_head()?;
                return Ok(());
            }
            _ => {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "reservation is missing or already finalized differently",
                )
                .into());
            }
        }
        transaction.execute(
            "UPDATE reservations SET state = ?3
             WHERE approval_id = ?1 AND operation_id = ?2",
            params![approval_id.as_str(), operation_id.as_str(), next.as_str()],
        )?;
        self.append_audit_transaction(
            &transaction,
            "reservation.finalized",
            &serde_json::json!({
                "approval_id": approval_id,
                "operation_id": operation_id,
                "state": next.as_str()
            }),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::ReservationFinalized)
    }

    pub fn reservation_status(
        &self,
        approval_id: &Digest32,
        operation_id: &OperationId,
    ) -> Result<Option<ReservationState>, JournalError> {
        let connection = self.lock()?;
        let value: Option<String> = connection
            .query_row(
                "SELECT state FROM reservations
                 WHERE approval_id = ?1 AND operation_id = ?2",
                params![approval_id.as_str(), operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| parse_reservation_state(&value))
            .transpose()
    }

    pub fn reservation_signature_count(
        &self,
        approval_id: &Digest32,
        operation_id: &OperationId,
    ) -> Result<Option<u64>, JournalError> {
        self.lock()?
            .query_row(
                "SELECT signature_count FROM reservations
                 WHERE approval_id = ?1 AND operation_id = ?2",
                params![approval_id.as_str(), operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| value.parse::<u64>().map_err(storage))
            .transpose()
    }

    pub fn publish_result(
        &self,
        approval_id: &Digest32,
        result: &SigningResult,
    ) -> Result<(), JournalError> {
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let operation = read_operation(&transaction, &result.operation_id)?
            .ok_or_else(|| protocol(ProtocolErrorCode::ApprovalNotFound, "operation not found"))?;
        if operation.operation_digest != result.operation_digest {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "result changed the stable operation digest",
            )
            .into());
        }
        let result_jcs = jcs_string(result)?;
        if let Some(prior) = operation.result {
            if jcs_string(&prior)? == result_jcs
                && reservation_state_by_id(&transaction, approval_id, &result.operation_id)?
                    == Some(ReservationState::Committed)
            {
                transaction.commit()?;
                drop(connection);
                self.checkpoint_committed_head()?;
                return Ok(());
            }
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "a different result is already published",
            )
            .into());
        }
        if operation.state != OperationState::Committed {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "result publication requires COMMITTED state",
            )
            .into());
        }
        require_reserved(&transaction, approval_id, &result.operation_id)?;
        let validation_receipt = retained_validation_receipt(&transaction, &result.operation_id)?;
        if validation_receipt.approval_id != *approval_id
            || validation_receipt.operation_digest != result.operation_digest
        {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "published result differs from its retained Broker validation receipt",
            )
            .into());
        }
        transaction.execute(
            "UPDATE operations SET state = 'SUCCEEDED', result_jcs = ?2
             WHERE operation_id = ?1",
            params![result.operation_id.as_str(), result_jcs],
        )?;
        transaction.execute(
            "UPDATE reservations SET state = 'COMMITTED'
             WHERE approval_id = ?1 AND operation_id = ?2",
            params![approval_id.as_str(), result.operation_id.as_str()],
        )?;
        self.append_audit_transaction(
            &transaction,
            "operation.published",
            &serde_json::json!({
                "approval_id": approval_id,
                "operation_id": result.operation_id,
                "operation_digest": result.operation_digest,
                "result_digest": Digest32::from_bytes(Sha256::digest(result_jcs.as_bytes()).into()),
                "signer_receipt_digest": result.signer_receipt_digest,
                "broker_receipt_digest": result.broker_receipt_digest,
                "validation_receipt_digest": validation_receipt.digest().map_err(signer_protocol)?,
                "reservation_state": "COMMITTED"
                ,"correlation_schema": "v1"
            }),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::OperationTransition)
    }

    pub fn publish_batch(
        &self,
        approval_id: &Digest32,
        parent_result: &SigningResult,
        child_results: &[SigningResult],
    ) -> Result<(), JournalError> {
        if child_results.is_empty() || child_results.len() > 32 {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "batch publication requires 1-32 children",
            )
            .into());
        }
        for (ordinal, child) in child_results.iter().enumerate() {
            if child.operation_id
                != derive_batch_child_operation_id(&parent_result.operation_id, ordinal)?
            {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "batch child operation ID is not the deterministic parent/index derivation",
                )
                .into());
            }
        }
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let parent =
            read_operation(&transaction, &parent_result.operation_id)?.ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::ApprovalNotFound,
                    "batch parent operation not found",
                )
            })?;
        if parent.operation_digest != parent_result.operation_digest {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "batch result changed the stable operation digest",
            )
            .into());
        }
        let prior: Option<String> = transaction
            .query_row(
                "SELECT result_jcs FROM operations WHERE operation_id = ?1",
                [parent_result.operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let parent_jcs = jcs_string(parent_result)?;
        if let Some(prior) = prior {
            let mut statement = transaction.prepare(
                "SELECT result_jcs FROM batch_children
                 WHERE parent_operation_id = ?1 ORDER BY ordinal",
            )?;
            let rows = statement.query_map([parent_result.operation_id.as_str()], |row| {
                row.get::<_, String>(0)
            })?;
            let existing_children = rows.collect::<Result<Vec<_>, _>>()?;
            let requested_children = child_results
                .iter()
                .map(jcs_string)
                .collect::<Result<Vec<_>, _>>()?;
            if prior == parent_jcs
                && existing_children == requested_children
                && reservation_state_by_id(&transaction, approval_id, &parent_result.operation_id)?
                    == Some(ReservationState::Committed)
            {
                drop(statement);
                transaction.commit()?;
                drop(connection);
                self.checkpoint_committed_head()?;
                return Ok(());
            }
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "a different batch result is already published",
            )
            .into());
        }
        if !parent.is_batch || parent.state != OperationState::Committed {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "batch publication requires a committed batch parent",
            )
            .into());
        }
        require_reserved(&transaction, approval_id, &parent_result.operation_id)?;
        let validation_receipt =
            retained_validation_receipt(&transaction, &parent_result.operation_id)?;
        if validation_receipt.approval_id != *approval_id
            || validation_receipt.operation_digest != parent_result.operation_digest
        {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "batch result differs from its retained Broker validation receipt",
            )
            .into());
        }
        for (ordinal, child) in child_results.iter().enumerate() {
            transaction.execute(
                "INSERT INTO batch_children(
                    parent_operation_id, child_operation_id, ordinal, result_jcs
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    parent_result.operation_id.as_str(),
                    child.operation_id.as_str(),
                    i64::try_from(ordinal).map_err(storage)?,
                    jcs_string(child)?
                ],
            )?;
        }
        transaction.execute(
            "UPDATE operations SET state = 'SUCCEEDED', result_jcs = ?2
             WHERE operation_id = ?1",
            params![parent_result.operation_id.as_str(), parent_jcs],
        )?;
        transaction.execute(
            "UPDATE reservations SET state = 'COMMITTED'
             WHERE approval_id = ?1 AND operation_id = ?2",
            params![approval_id.as_str(), parent_result.operation_id.as_str()],
        )?;
        self.append_audit_transaction(
            &transaction,
            "batch.published",
            &serde_json::json!({
                "approval_id": approval_id,
                "parent_operation_id": parent_result.operation_id,
                "parent_operation_digest": parent_result.operation_digest,
                "parent_result_digest": Digest32::from_bytes(Sha256::digest(parent_jcs.as_bytes()).into()),
                "parent_signer_receipt_digest": parent_result.signer_receipt_digest,
                "parent_broker_receipt_digest": parent_result.broker_receipt_digest,
                "validation_receipt_digest": validation_receipt.digest().map_err(signer_protocol)?,
                "children": child_results.iter().enumerate().map(|(ordinal, child)| {
                    let canonical = jcs_string(child).expect("validated SigningResult serializes");
                    serde_json::json!({
                        "ordinal": ordinal,
                        "operation_id": child.operation_id,
                        "operation_digest": child.operation_digest,
                        "result_digest": Digest32::from_bytes(Sha256::digest(canonical.as_bytes()).into()),
                        "signer_receipt_digest": child.signer_receipt_digest,
                        "broker_receipt_digest": child.broker_receipt_digest
                    })
                }).collect::<Vec<_>>(),
                "child_count": child_results.len(),
                "reservation_state": "COMMITTED",
                "correlation_schema": "v1"
            }),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        self.after_durable(DurablePoint::BatchPublished)
    }

    pub fn batch_children(
        &self,
        parent_operation_id: &OperationId,
    ) -> Result<Vec<SigningResult>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT result_jcs FROM batch_children
             WHERE parent_operation_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement.query_map([parent_operation_id.as_str()], |row| {
            row.get::<_, String>(0)
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(serde_json::from_str(&row?).map_err(storage)?);
        }
        Ok(results)
    }

    pub fn batch_child(
        &self,
        child_operation_id: &OperationId,
    ) -> Result<Option<SigningResult>, JournalError> {
        let connection = self.lock()?;
        let value: Option<String> = connection
            .query_row(
                "SELECT result_jcs FROM batch_children WHERE child_operation_id = ?1",
                [child_operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| serde_json::from_str(&value).map_err(storage))
            .transpose()
    }

    pub fn audit_entries(&self) -> Result<Vec<AuditEntry>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT sequence, event_type, payload_jcs, previous_hash, entry_hash,
                    signing_key_id, signature
             FROM audit_chain ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (
                sequence,
                event_type,
                payload_jcs,
                previous_hash,
                entry_hash,
                signing_key_id,
                signature,
            ) = row?;
            entries.push(AuditEntry {
                sequence: u64::try_from(sequence).map_err(storage)?,
                event_type,
                payload_jcs,
                previous_hash: Digest32::new(previous_hash)?,
                entry_hash: Digest32::new(entry_hash)?,
                signing_key_id: Token::new(signing_key_id)?,
                signature: Base64UrlBytes::parse(signature)?,
            });
        }
        Ok(entries)
    }

    pub fn verify_audit_chain(&self) -> Result<(), JournalError> {
        let connection = self.lock()?;
        let result = verify_audit_chain_connection(&connection, self.audit_signer.as_ref());
        if result.is_err() {
            self.audit_degraded.store(true, Ordering::SeqCst);
        }
        result
    }

    pub fn observe_time(
        &self,
        reading: TimeReading,
        max_forward_step_ms: u64,
        rate_limited_mutation: bool,
    ) -> Result<ClockDecision, JournalError> {
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let decision = |effective_now_ms, condition| ClockDecision {
            effective_now_ms,
            condition,
            observed_utc_ms: reading.utc_ms,
            monotonic_anchor_ns: reading.monotonic_anchor_ns,
            boot_epoch: reading.boot_epoch.clone(),
        };
        let stored: Option<(String, String, String)> = transaction
            .query_row(
                "SELECT last_effective_ms, condition, monotonic_anchor_ns
                 FROM clock_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let initializing = stored.is_none();
        let stored_condition = stored.as_ref().map(|(_, condition, _)| condition.as_str());
        let previous = stored
            .as_ref()
            .map(|(value, _, anchor)| {
                Ok::<_, JournalError>(PersistedClockState {
                    last_effective_ms: value.parse().map_err(storage)?,
                    monotonic_anchor_ns: anchor.parse().map_err(storage)?,
                })
            })
            .transpose()?;
        let platform_reading = bloom_trusted_time::PlatformTimeReading {
            utc_ms: reading.utc_ms,
            monotonic_anchor_ns: reading.monotonic_anchor_ns,
            monotonic_elapsed_ms: reading.monotonic_elapsed_ms,
        };
        let shared = evaluate_durable_clock(previous, &platform_reading, max_forward_step_ms)
            .map_err(|cause| protocol(ProtocolErrorCode::ClockUntrusted, cause.to_string()))?;
        let condition = broker_clock_condition(shared.condition);
        let effective_now_ms = shared.effective_now_ms;

        if shared.condition == DurableClockCondition::Untrusted {
            write_clock_state(&transaction, effective_now_ms, condition, &reading)?;
            if stored_condition != Some("UNTRUSTED") {
                self.append_audit_transaction(
                    &transaction,
                    "clock.untrusted",
                    &serde_json::json!({
                        "effective_now_ms": effective_now_ms.to_string(),
                        "observed_utc_ms": null,
                        "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                        "boot_epoch": reading.boot_epoch
                    }),
                    self.audit_signer.as_ref(),
                )?;
            }
            transaction.commit()?;
            drop(connection);
            self.checkpoint_committed_head()?;
            if rate_limited_mutation {
                return Err(protocol(
                    ProtocolErrorCode::ClockUntrusted,
                    "trusted platform time source is unavailable",
                )
                .into());
            }
            return Ok(decision(effective_now_ms, condition));
        }

        let utc_ms = reading.utc_ms.ok_or_else(|| {
            protocol(
                ProtocolErrorCode::ClockUntrusted,
                "durable clock returned a trusted decision without UTC",
            )
        })?;
        match shared.condition {
            DurableClockCondition::Healthy => {
                write_clock_state(&transaction, effective_now_ms, condition, &reading)?;
                if initializing {
                    self.append_audit_transaction(
                        &transaction,
                        "clock.initialized",
                        &serde_json::json!({
                            "effective_now_ms": effective_now_ms.to_string(),
                            "observed_utc_ms": utc_ms.to_string(),
                            "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                            "boot_epoch": reading.boot_epoch
                        }),
                        self.audit_signer.as_ref(),
                    )?;
                }
                transaction.commit()?;
                drop(connection);
                self.checkpoint_committed_head()?;
                Ok(decision(effective_now_ms, condition))
            }
            DurableClockCondition::RollbackFrozen => {
                write_clock_state(&transaction, effective_now_ms, condition, &reading)?;
                if stored_condition != Some("ROLLBACK_FROZEN") {
                    self.append_audit_transaction(
                        &transaction,
                        "clock.rollback",
                        &serde_json::json!({
                            "observed_utc_ms": utc_ms.to_string(),
                            "effective_now_ms": effective_now_ms.to_string(),
                            "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                            "boot_epoch": reading.boot_epoch
                        }),
                        self.audit_signer.as_ref(),
                    )?;
                }
                transaction.commit()?;
                drop(connection);
                self.checkpoint_committed_head()?;
                if rate_limited_mutation {
                    return Err(protocol(
                        ProtocolErrorCode::ClockRollback,
                        "UTC rollback detected; effective time is frozen",
                    )
                    .into());
                }
                Ok(decision(effective_now_ms, condition))
            }
            DurableClockCondition::ForwardJumpRejected => {
                write_clock_state(&transaction, effective_now_ms, condition, &reading)?;
                if stored_condition != Some("FORWARD_JUMP_REJECTED") {
                    self.append_audit_transaction(
                        &transaction,
                        "clock.forward_jump",
                        &serde_json::json!({
                            "observed_utc_ms": utc_ms.to_string(),
                            "effective_now_ms": effective_now_ms.to_string(),
                            "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                            "boot_epoch": reading.boot_epoch
                        }),
                        self.audit_signer.as_ref(),
                    )?;
                }
                transaction.commit()?;
                drop(connection);
                self.checkpoint_committed_head()?;
                Ok(decision(effective_now_ms, condition))
            }
            DurableClockCondition::Untrusted => unreachable!("handled above"),
        }
    }

    pub fn repair_clock(&self, accepted_utc_ms: u64) -> Result<ClockDecision, JournalError> {
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let prior: Option<(String, String, String)> = transaction
            .query_row(
                "SELECT last_effective_ms, monotonic_anchor_ns, boot_epoch
                 FROM clock_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (prior, monotonic_anchor_ns, boot_epoch) = prior.ok_or_else(|| {
            protocol(
                ProtocolErrorCode::ClockUntrusted,
                "clock repair requires an initialized durable clock",
            )
        })?;
        let prior = prior.parse::<u64>().map_err(storage)?;
        let reading = TimeReading {
            utc_ms: Some(accepted_utc_ms),
            monotonic_elapsed_ms: 0,
            monotonic_anchor_ns: monotonic_anchor_ns.parse::<u64>().map_err(storage)?,
            boot_epoch: BootEpoch::new(boot_epoch)?,
        };
        if accepted_utc_ms < prior {
            return Err(protocol(
                ProtocolErrorCode::ClockRollback,
                "clock repair cannot move effective time backwards",
            )
            .into());
        }
        write_clock_state(
            &transaction,
            accepted_utc_ms,
            ClockCondition::Repaired,
            &reading,
        )?;
        self.append_audit_transaction(
            &transaction,
            "clock.repaired",
            &serde_json::json!({
                "prior_effective_ms": prior.to_string(),
                "accepted_utc_ms": accepted_utc_ms.to_string(),
                "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                "boot_epoch": reading.boot_epoch
            }),
            self.audit_signer.as_ref(),
        )?;
        transaction.commit()?;
        drop(connection);
        self.checkpoint_committed_head()?;
        Ok(ClockDecision {
            effective_now_ms: accepted_utc_ms,
            condition: ClockCondition::Repaired,
            observed_utc_ms: reading.utc_ms,
            monotonic_anchor_ns: reading.monotonic_anchor_ns,
            boot_epoch: reading.boot_epoch,
        })
    }

    pub fn active_approvals_expiring_by(
        &self,
        accepted_utc_ms: u64,
    ) -> Result<Vec<Digest32>, JournalError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT approvals.approval_id, approval_metadata.terms_jcs
             FROM approvals JOIN approval_metadata USING(approval_id)
             WHERE approvals.state = 'ACTIVE' ORDER BY approvals.approval_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut expiring = Vec::new();
        for row in rows {
            let (approval_id, terms_jcs) = row?;
            let terms: SealedApprovalTerms = serde_json::from_str(&terms_jcs).map_err(storage)?;
            if terms.expires_at_ms.get() <= accepted_utc_ms {
                expiring.push(Digest32::new(approval_id)?);
            }
        }
        Ok(expiring)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, JournalError> {
        self.connection
            .lock()
            .map_err(|_| JournalError::Storage("journal mutex poisoned".into()))
    }

    pub(crate) fn lock_for_mutation(&self) -> Result<MutexGuard<'_, Connection>, JournalError> {
        if self.audit_degraded.load(Ordering::SeqCst) {
            return Err(audit_degraded());
        }
        let connection = self.lock()?;
        if let Err(error) = verify_audit_chain_connection(&connection, self.audit_signer.as_ref()) {
            self.audit_degraded.store(true, Ordering::SeqCst);
            return Err(error);
        }
        Ok(connection)
    }

    pub(crate) fn shared_connection(&self) -> Arc<Mutex<Connection>> {
        self.connection.clone()
    }

    /// Verify the already-locked journal target used during legacy migration.
    /// Runtime mutations must obtain a verified guard through
    /// `lock_for_mutation` instead.
    pub(crate) fn verify_migration_target(
        &self,
        connection: &Connection,
    ) -> Result<(), JournalError> {
        if self.audit_degraded.load(Ordering::SeqCst) {
            return Err(audit_degraded());
        }
        if let Err(error) = verify_audit_chain_connection(connection, self.audit_signer.as_ref()) {
            self.audit_degraded.store(true, Ordering::SeqCst);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn append_external_audit(
        &self,
        transaction: &Transaction<'_>,
        event_type: &str,
        payload: &impl Serialize,
    ) -> Result<(), JournalError> {
        self.append_audit_transaction(transaction, event_type, payload, self.audit_signer.as_ref())
    }

    fn append_audit_transaction(
        &self,
        transaction: &Transaction<'_>,
        event_type: &str,
        payload: &impl Serialize,
        audit_signer: &dyn AuditSigner,
    ) -> Result<(), JournalError> {
        append_audit(transaction, event_type, payload, audit_signer)?;
        Ok(())
    }

    /// Persist the fully committed local head. This must run only after the
    /// SQLite transaction commits: checkpointing a speculative transaction
    /// can retain a head for a rollback and permanently reject the next
    /// legitimate mutation as a sequence rollback.
    pub(crate) fn checkpoint_committed_head(&self) -> Result<(), JournalError> {
        // Keep the journal mutex until the independently durable append has
        // completed. Otherwise mutation A can read head N, mutation B can
        // commit and checkpoint N+1, and then A can publish stale head N. The
        // checkpoint store correctly rejects that ordering as a rollback.
        let connection = self.lock()?;
        if let Err(error) = verify_audit_chain_connection(&connection, self.audit_signer.as_ref()) {
            self.audit_degraded.store(true, Ordering::SeqCst);
            return Err(error);
        }
        let (sequence, head_hash) = connection
            .query_row(
                "SELECT sequence, entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(
                |(sequence, hash)| -> Result<(u64, Digest32), JournalError> {
                    Ok((
                        u64::try_from(sequence)
                            .map_err(storage)?
                            .checked_add(1)
                            .ok_or_else(|| JournalError::Storage("audit head overflow".into()))?,
                        Digest32::new(hash)?,
                    ))
                },
            )
            .transpose()?
            .unwrap_or_else(|| {
                (
                    0,
                    Digest32::new("00".repeat(32)).expect("fixed zero digest is valid"),
                )
            });
        let installed = self
            .self_checkpoint
            .lock()
            .map_err(|_| storage("Broker self-checkpoint mutex poisoned"))?
            .clone();
        if let Some(installed) = installed {
            let signed_head = sign_journal_head(&installed.identity, sequence, head_hash);
            if let Err(error) = installed.checkpoints.append_peer_head(&signed_head) {
                self.audit_degraded.store(true, Ordering::SeqCst);
                let retained = installed
                    .checkpoints
                    .latest_peer_head(&signed_head.service_id)
                    .ok()
                    .flatten()
                    .map(|head| {
                        format!(
                            "{}:{}:{}:{}",
                            head.service_id,
                            head.key_id,
                            head.sequence.get(),
                            head.head_hash
                        )
                    })
                    .unwrap_or_else(|| "none".into());
                return Err(storage(format!(
                    "persist Broker self-checkpoint before publishing mutation success: {error}; attempted={}:{}:{}:{} retained={retained}",
                    signed_head.service_id,
                    signed_head.key_id,
                    signed_head.sequence.get(),
                    signed_head.head_hash
                )));
            }
        }
        Ok(())
    }

    fn after_durable(&self, point: DurablePoint) -> Result<(), JournalError> {
        if let Some(hook) = &self.fault_hook {
            hook.after_durable(point)
                .map_err(|message| JournalError::InjectedCrash { point, message })?;
        }
        Ok(())
    }
}

fn ensure_column(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), JournalError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if !columns.iter().any(|candidate| candidate == column) {
        connection.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
    }
    Ok(())
}

pub fn derive_batch_child_operation_id(
    parent_operation_id: &OperationId,
    ordinal: usize,
) -> Result<OperationId, JournalError> {
    let ordinal = u32::try_from(ordinal).map_err(storage)?;
    let mut hasher = Sha256::new();
    hasher.update(BATCH_CHILD_DOMAIN);
    hasher.update(parent_operation_id.as_str().as_bytes());
    hasher.update(ordinal.to_be_bytes());
    OperationId::new(hex::encode(hasher.finalize())).map_err(Into::into)
}

fn protocol(code: ProtocolErrorCode, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}

fn storage(error: impl std::fmt::Display) -> JournalError {
    JournalError::Storage(error.to_string())
}

fn signer_protocol(error: bloom_signer_api::ProtocolError) -> JournalError {
    JournalError::Protocol(crate::translation::error::signer_error_to_machine(error))
}

fn jcs_string(value: &impl Serialize) -> Result<String, JournalError> {
    String::from_utf8(serde_jcs::to_vec(value).map_err(storage)?).map_err(storage)
}

fn attempt_retry_binding_digest(request: &UnsignedSignRequest) -> Result<Digest32, JournalError> {
    let mut value = serde_json::to_value(request).map_err(storage)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| JournalError::Storage("sign attempt must serialize as an object".into()))?;
    for permitted_retry_field in [
        "attempt_id",
        "attempt_digest",
        "issuer_boot_epoch",
        "issued_at_ms",
        "not_before_ms",
        "expires_at_ms",
    ] {
        object.remove(permitted_retry_field);
    }
    let mut hasher = Sha256::new();
    hasher.update(ATTEMPT_BINDING_DOMAIN);
    hasher.update(serde_jcs::to_vec(&value).map_err(storage)?);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn append_audit(
    transaction: &Transaction<'_>,
    event_type: &str,
    payload: &impl Serialize,
    audit_signer: &dyn AuditSigner,
) -> Result<(u64, Digest32), JournalError> {
    let (sequence, previous_hash) = transaction
        .query_row(
            "SELECT sequence, entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)? + 1, row.get::<_, String>(1)?)),
        )
        .optional()?
        .unwrap_or((0_i64, "00".repeat(32)));
    let sequence = u64::try_from(sequence).map_err(storage)?;
    let previous_hash = Digest32::new(previous_hash)?;
    let payload_jcs = jcs_string(payload)?;
    let entry_hash = compute_audit_hash(sequence, event_type, &payload_jcs, &previous_hash);
    let signing_key_id = audit_signer.key_id();
    let signature = audit_signer
        .sign(&audit_signature_message(&entry_hash))
        .map_err(storage)?;
    transaction.execute(
        "INSERT INTO audit_chain(
            sequence, event_type, payload_jcs, previous_hash, entry_hash,
            signing_key_id, signature
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            i64::try_from(sequence).map_err(storage)?,
            event_type,
            payload_jcs,
            previous_hash.as_str(),
            entry_hash.as_str(),
            signing_key_id.as_str(),
            signature.encoded()
        ],
    )?;
    Ok((sequence + 1, entry_hash))
}

fn verify_audit_chain_connection(
    connection: &Connection,
    audit_signer: &dyn AuditSigner,
) -> Result<(), JournalError> {
    let mut statement = connection.prepare(
        "SELECT sequence, event_type, payload_jcs, previous_hash, entry_hash,
                signing_key_id, signature
         FROM audit_chain ORDER BY sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let mut expected_sequence = 0_u64;
    let mut expected_previous = Digest32::new("00".repeat(32))?;
    let mut expected_key_id: Option<Token> = None;
    let mut pending_rotation: Option<(Token, Token, Digest32)> = None;
    for row in rows {
        let (sequence, event_type, payload_jcs, previous_hash, entry_hash, key_id, signature) =
            row?;
        let sequence = u64::try_from(sequence).map_err(storage)?;
        let previous_hash = Digest32::new(previous_hash)?;
        let entry_hash = Digest32::new(entry_hash)?;
        let key_id = Token::new(key_id)?;
        let signature = Base64UrlBytes::parse(signature)?;
        if expected_key_id.is_none() {
            expected_key_id = Some(key_id.clone());
        }
        if sequence != expected_sequence
            || previous_hash != expected_previous
            || compute_audit_hash(sequence, &event_type, &payload_jcs, &previous_hash) != entry_hash
            || expected_key_id.as_ref() != Some(&key_id)
            || audit_signer
                .verify(&key_id, &audit_signature_message(&entry_hash), &signature)
                .is_err()
        {
            return Err(audit_degraded());
        }
        verify_audit_correlation(connection, &event_type, &payload_jcs)?;
        if pending_rotation.is_some() && event_type != "audit.key_rotation_completed" {
            return Err(audit_degraded());
        }
        if event_type == "audit.key_rotated" {
            #[derive(Deserialize)]
            struct Rotation {
                old_key_id: Token,
                new_key_id: Token,
                prior_head: Digest32,
                new_key_confirmation: Base64UrlBytes,
            }
            let rotation: Rotation = serde_json::from_str(&payload_jcs).map_err(storage)?;
            if rotation.old_key_id != key_id
                || rotation.prior_head != previous_hash
                || rotation.new_key_id == rotation.old_key_id
                || audit_signer
                    .verify(
                        &rotation.new_key_id,
                        &audit_rotation_message(
                            &rotation.old_key_id,
                            &rotation.new_key_id,
                            &rotation.prior_head,
                        ),
                        &rotation.new_key_confirmation,
                    )
                    .is_err()
            {
                return Err(audit_degraded());
            }
            pending_rotation = Some((
                rotation.old_key_id.clone(),
                rotation.new_key_id.clone(),
                entry_hash.clone(),
            ));
            expected_key_id = Some(rotation.new_key_id);
        } else if event_type == "audit.key_rotation_completed" {
            #[derive(Deserialize)]
            struct Completion {
                old_key_id: Token,
                new_key_id: Token,
                final_old_head: Digest32,
            }
            let completion: Completion =
                serde_json::from_str(&payload_jcs).map_err(|_| audit_degraded())?;
            let Some((old_key_id, new_key_id, final_old_head)) = pending_rotation.take() else {
                return Err(audit_degraded());
            };
            if completion.old_key_id != old_key_id
                || completion.new_key_id != new_key_id
                || completion.new_key_id != key_id
                || completion.old_key_id == completion.new_key_id
                || completion.final_old_head != final_old_head
                || completion.final_old_head != previous_hash
            {
                return Err(audit_degraded());
            }
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| JournalError::Storage("audit sequence overflow".into()))?;
        expected_previous = entry_hash;
    }
    if pending_rotation.is_some()
        || expected_key_id
            .as_ref()
            .is_some_and(|expected| expected != &audit_signer.key_id())
    {
        return Err(audit_degraded());
    }
    Ok(())
}

fn verify_audit_correlation(
    connection: &Connection,
    event_type: &str,
    payload_jcs: &str,
) -> Result<(), JournalError> {
    let payload: serde_json::Value =
        serde_json::from_str(payload_jcs).map_err(|_| audit_degraded())?;
    if payload
        .get("correlation_schema")
        .and_then(|value| value.as_str())
        != Some("v1")
    {
        return Ok(());
    }
    let correlated = match event_type {
        "operation.received" => {
            let operation_id = payload
                .get("operation_id")
                .and_then(|value| value.as_str())
                .ok_or_else(audit_degraded)?;
            let operation_id =
                OperationId::new(operation_id.to_owned()).map_err(|_| audit_degraded())?;
            let validation_receipt = retained_validation_receipt(connection, &operation_id)?;
            payload.get("operation_digest")
                == Some(&serde_json::json!(validation_receipt.operation_digest))
                && payload.get("validation_receipt_digest")
                    == Some(&serde_json::json!(
                        validation_receipt.digest().map_err(signer_protocol)?
                    ))
        }
        "operation.published" => {
            let operation_id = payload
                .get("operation_id")
                .and_then(|value| value.as_str())
                .ok_or_else(audit_degraded)?;
            let result_jcs: String = connection
                .query_row(
                    "SELECT result_jcs FROM operations WHERE operation_id=?1",
                    [operation_id],
                    |row| row.get(0),
                )
                .map_err(|_| audit_degraded())?;
            let result: SigningResult =
                serde_json::from_str(&result_jcs).map_err(|_| audit_degraded())?;
            let validation_receipt = retained_validation_receipt(
                connection,
                &OperationId::new(operation_id.to_owned()).map_err(|_| audit_degraded())?,
            )?;
            payload.get("operation_digest") == Some(&serde_json::json!(result.operation_digest))
                && payload.get("result_digest")
                    == Some(&serde_json::json!(Digest32::from_bytes(
                        Sha256::digest(result_jcs.as_bytes()).into()
                    )))
                && payload.get("signer_receipt_digest")
                    == Some(&serde_json::json!(result.signer_receipt_digest))
                && payload.get("broker_receipt_digest")
                    == Some(&serde_json::json!(result.broker_receipt_digest))
                && payload.get("validation_receipt_digest")
                    == Some(&serde_json::json!(
                        validation_receipt.digest().map_err(signer_protocol)?
                    ))
        }
        "batch.published" => {
            let parent_id = payload
                .get("parent_operation_id")
                .and_then(|value| value.as_str())
                .ok_or_else(audit_degraded)?;
            let parent_jcs: String = connection
                .query_row(
                    "SELECT result_jcs FROM operations WHERE operation_id=?1",
                    [parent_id],
                    |row| row.get(0),
                )
                .map_err(|_| audit_degraded())?;
            let parent: SigningResult =
                serde_json::from_str(&parent_jcs).map_err(|_| audit_degraded())?;
            let validation_receipt = retained_validation_receipt(
                connection,
                &OperationId::new(parent_id.to_owned()).map_err(|_| audit_degraded())?,
            )?;
            let mut statement = connection
                .prepare(
                    "SELECT ordinal, result_jcs FROM batch_children
                     WHERE parent_operation_id=?1 ORDER BY ordinal",
                )
                .map_err(|_| audit_degraded())?;
            let rows = statement
                .query_map([parent_id], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| audit_degraded())?;
            let mut children = Vec::new();
            for row in rows {
                let (ordinal, canonical) = row.map_err(|_| audit_degraded())?;
                let child: SigningResult =
                    serde_json::from_str(&canonical).map_err(|_| audit_degraded())?;
                children.push(serde_json::json!({
                    "ordinal": ordinal,
                    "operation_id": child.operation_id,
                    "operation_digest": child.operation_digest,
                    "result_digest": Digest32::from_bytes(Sha256::digest(canonical.as_bytes()).into()),
                    "signer_receipt_digest": child.signer_receipt_digest,
                    "broker_receipt_digest": child.broker_receipt_digest
                }));
            }
            payload.get("parent_operation_digest")
                == Some(&serde_json::json!(parent.operation_digest))
                && payload.get("parent_result_digest")
                    == Some(&serde_json::json!(Digest32::from_bytes(
                        Sha256::digest(parent_jcs.as_bytes()).into()
                    )))
                && payload.get("parent_signer_receipt_digest")
                    == Some(&serde_json::json!(parent.signer_receipt_digest))
                && payload.get("parent_broker_receipt_digest")
                    == Some(&serde_json::json!(parent.broker_receipt_digest))
                && payload.get("validation_receipt_digest")
                    == Some(&serde_json::json!(
                        validation_receipt.digest().map_err(signer_protocol)?
                    ))
                && payload.get("children") == Some(&serde_json::Value::Array(children))
        }
        "approval.transition"
            if payload.get("to").and_then(|value| value.as_str()) == Some("ACTIVE") =>
        {
            let approval_id = payload
                .get("approval_id")
                .and_then(|value| value.as_str())
                .ok_or_else(audit_degraded)?;
            let receipt_jcs: String = connection
                .query_row(
                    "SELECT ceremony_grant_jcs FROM approval_metadata WHERE approval_id=?1",
                    [approval_id],
                    |row| row.get(0),
                )
                .map_err(|_| audit_degraded())?;
            payload.get("signer_activation_receipt_digest")
                == Some(&serde_json::json!(Digest32::from_bytes(
                    Sha256::digest(receipt_jcs.as_bytes()).into()
                )))
        }
        _ => true,
    };
    if correlated {
        Ok(())
    } else {
        Err(audit_degraded())
    }
}

fn audit_degraded() -> JournalError {
    protocol(
        ProtocolErrorCode::MalformedFrame,
        "Broker audit chain verification failed; security mutations are disabled",
    )
    .into()
}

fn audit_signature_message(entry_hash: &Digest32) -> Vec<u8> {
    [AUDIT_SIGNATURE_DOMAIN, entry_hash.as_str().as_bytes()].concat()
}

fn audit_rotation_message(
    old_key_id: &Token,
    new_key_id: &Token,
    prior_head: &Digest32,
) -> Vec<u8> {
    [
        AUDIT_ROTATION_DOMAIN,
        old_key_id.as_str().as_bytes(),
        new_key_id.as_str().as_bytes(),
        prior_head.as_str().as_bytes(),
    ]
    .concat()
}

fn broker_clock_condition(condition: DurableClockCondition) -> ClockCondition {
    match condition {
        DurableClockCondition::Healthy => ClockCondition::Healthy,
        DurableClockCondition::Untrusted => ClockCondition::Untrusted,
        DurableClockCondition::RollbackFrozen => ClockCondition::RollbackFrozen,
        DurableClockCondition::ForwardJumpRejected => ClockCondition::ForwardJumpRejected,
    }
}

fn write_clock_state(
    transaction: &Transaction<'_>,
    effective_now_ms: u64,
    condition: ClockCondition,
    reading: &TimeReading,
) -> Result<(), JournalError> {
    transaction.execute(
        "INSERT INTO clock_state(
             singleton, last_effective_ms, condition, observed_utc_ms,
             monotonic_anchor_ns, boot_epoch
         )
         VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(singleton) DO UPDATE SET
             last_effective_ms = excluded.last_effective_ms,
             condition = excluded.condition,
             observed_utc_ms = excluded.observed_utc_ms,
             monotonic_anchor_ns = excluded.monotonic_anchor_ns,
             boot_epoch = excluded.boot_epoch",
        params![
            effective_now_ms.to_string(),
            match condition {
                ClockCondition::Healthy => "HEALTHY",
                ClockCondition::ForwardJumpRejected => "FORWARD_JUMP_REJECTED",
                ClockCondition::Untrusted => "UNTRUSTED",
                ClockCondition::RollbackFrozen => "ROLLBACK_FROZEN",
                ClockCondition::Repaired => "REPAIRED",
            },
            reading.utc_ms.map(|value| value.to_string()),
            reading.monotonic_anchor_ns.to_string(),
            reading.boot_epoch.as_str(),
        ],
    )?;
    Ok(())
}

fn compute_audit_hash(
    sequence: u64,
    event_type: &str,
    payload_jcs: &str,
    previous_hash: &Digest32,
) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_DOMAIN);
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_hash.as_str().as_bytes());
    hasher.update(event_type.as_bytes());
    hasher.update(payload_jcs.as_bytes());
    Digest32::from_bytes(hasher.finalize().into())
}

fn read_operation(
    connection: &Connection,
    operation_id: &OperationId,
) -> Result<Option<OperationSnapshot>, JournalError> {
    let row = connection
        .query_row(
            "SELECT operation_digest, retry_binding_digest, state, is_batch, result_jcs
             FROM operations WHERE operation_id = ?1",
            [operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(|(digest, retry_binding_digest, state, is_batch, result)| {
        Ok(OperationSnapshot {
            operation_id: operation_id.clone(),
            operation_digest: Digest32::new(digest)?,
            state: parse_operation_state(&state)?,
            is_batch,
            retry_binding_digest: Digest32::new(retry_binding_digest)?,
            result: result
                .map(|value| serde_json::from_str(&value).map_err(storage))
                .transpose()?,
        })
    })
    .transpose()
}

fn retained_validation_receipt(
    connection: &Connection,
    operation_id: &OperationId,
) -> Result<BrokerValidationReceipt, JournalError> {
    let canonical: String = connection
        .query_row(
            "SELECT validation_receipt_jcs FROM operations WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|_| audit_degraded())?;
    serde_json::from_str(&canonical).map_err(|_| audit_degraded())
}

fn reservation_state(
    transaction: &Transaction<'_>,
    request: &ReservationRequest,
) -> Result<Option<ReservationState>, JournalError> {
    let value: Option<String> = transaction
        .query_row(
            "SELECT state FROM reservations WHERE approval_id = ?1 AND operation_id = ?2",
            params![request.approval_id.as_str(), request.operation_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| parse_reservation_state(&value))
        .transpose()
}

fn reservation_state_by_id(
    transaction: &Transaction<'_>,
    approval_id: &Digest32,
    operation_id: &OperationId,
) -> Result<Option<ReservationState>, JournalError> {
    let value: Option<String> = transaction
        .query_row(
            "SELECT state FROM reservations WHERE approval_id = ?1 AND operation_id = ?2",
            params![approval_id.as_str(), operation_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| parse_reservation_state(&value))
        .transpose()
}

fn require_reserved(
    transaction: &Transaction<'_>,
    approval_id: &Digest32,
    operation_id: &OperationId,
) -> Result<(), JournalError> {
    if reservation_state_by_id(transaction, approval_id, operation_id)?
        != Some(ReservationState::Reserved)
    {
        return Err(protocol(
            ProtocolErrorCode::OperationIdConflict,
            "result publication requires an active accounting reservation",
        )
        .into());
    }
    Ok(())
}

fn parse_reservation_state(value: &str) -> Result<ReservationState, JournalError> {
    match value {
        "RESERVED" => Ok(ReservationState::Reserved),
        "COMMITTED" => Ok(ReservationState::Committed),
        "RELEASED" => Ok(ReservationState::Released),
        "QUARANTINED" => Ok(ReservationState::Quarantined),
        _ => Err(JournalError::Storage("invalid reservation state".into())),
    }
}

fn validate_value_limits(
    transaction: &Transaction<'_>,
    request: &ReservationRequest,
    limits: &BudgetLimits,
) -> Result<(), JournalError> {
    for (asset_id, requested) in &request.values {
        let limit = limits.value_limits.get(asset_id).ok_or_else(|| {
            protocol(
                ProtocolErrorCode::LimitExceededValue,
                format!("asset {asset_id} is not approved"),
            )
        })?;
        let mut statement = transaction.prepare(
            "SELECT value.amount
             FROM reservation_values value
             JOIN reservations reservation
               ON reservation.approval_id = value.approval_id
              AND reservation.operation_id = value.operation_id
             WHERE value.approval_id = ?1 AND value.asset_id = ?2
               AND reservation.state != 'RELEASED'",
        )?;
        let rows = statement.query_map(params![request.approval_id.as_str(), asset_id], |row| {
            row.get::<_, String>(0)
        })?;
        let mut total = BigUint::from(0_u8);
        for row in rows {
            total += BigUint::from_str(&row?).map_err(storage)?;
        }
        total += BigUint::from_str(requested.as_str()).map_err(storage)?;
        if total > BigUint::from_str(limit.as_str()).map_err(storage)? {
            return Err(protocol(
                ProtocolErrorCode::LimitExceededValue,
                format!("value limit exceeded for asset {asset_id}"),
            )
            .into());
        }
    }
    Ok(())
}

fn validate_reservation_clock(
    transaction: &Transaction<'_>,
    reserved_at_ms: u64,
    trusted_time_required: bool,
) -> Result<(), JournalError> {
    let clock: Option<(String, String)> = transaction
        .query_row(
            "SELECT last_effective_ms, condition FROM clock_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if trusted_time_required && clock.is_none() {
        return Err(protocol(
            ProtocolErrorCode::ClockUntrusted,
            "rate-limited reservation requires initialized trusted time",
        )
        .into());
    }
    if let Some((effective, condition)) = clock {
        if trusted_time_required
            && !matches!(
                condition.as_str(),
                "HEALTHY" | "FORWARD_JUMP_REJECTED" | "REPAIRED"
            )
        {
            return Err(protocol(
                ProtocolErrorCode::ClockUntrusted,
                format!("rate-limited reservation denied while clock is {condition}"),
            )
            .into());
        }
        if effective != reserved_at_ms.to_string() {
            return Err(protocol(
                ProtocolErrorCode::ClockUntrusted,
                "reservation timestamp is not the journal's durable effective time",
            )
            .into());
        }
    }
    Ok(())
}

fn reservation_matches(
    transaction: &Transaction<'_>,
    request: &ReservationRequest,
) -> Result<bool, JournalError> {
    let header: (String, String) = transaction.query_row(
        "SELECT operation_digest, signature_count
         FROM reservations
         WHERE approval_id = ?1 AND operation_id = ?2",
        params![request.approval_id.as_str(), request.operation_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if header.0 != request.operation_digest.as_str()
        || header.1 != request.signature_count.to_string()
    {
        return Ok(false);
    }
    let mut statement = transaction.prepare(
        "SELECT asset_id, amount FROM reservation_values
         WHERE approval_id = ?1 AND operation_id = ?2 ORDER BY asset_id",
    )?;
    let rows = statement.query_map(
        params![request.approval_id.as_str(), request.operation_id.as_str()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    let stored = rows.collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(stored
        == request
            .values
            .iter()
            .map(|(asset, amount)| (asset.clone(), amount.as_str().to_owned()))
            .collect())
}

fn validate_rate_limits(
    transaction: &Transaction<'_>,
    request: &ReservationRequest,
    limits: &BudgetLimits,
) -> Result<(), JournalError> {
    if limits.rate_limits.is_empty() {
        return Ok(());
    }
    let mut statement = transaction.prepare(
        "WITH RECURSIVE lineage(approval_id) AS (
            VALUES (?1)
            UNION ALL
            SELECT metadata.renewal_of
            FROM approval_metadata metadata
            JOIN lineage ON metadata.approval_id = lineage.approval_id
            WHERE metadata.renewal_of IS NOT NULL
         )
         SELECT signature_count, reserved_at_ms FROM reservations
         WHERE approval_id IN (SELECT approval_id FROM lineage)
           AND state != 'RELEASED'",
    )?;
    let rows = statement.query_map([request.approval_id.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let existing = rows
        .map(|row| {
            let (signatures, reserved_at) = row?;
            Ok((
                signatures.parse::<u64>().map_err(storage)?,
                reserved_at.parse::<u64>().map_err(storage)?,
            ))
        })
        .collect::<Result<Vec<_>, JournalError>>()?;
    for limit in &limits.rate_limits {
        if limit.duration_ms == 0 || limit.max_operations == 0 || limit.max_signatures == 0 {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "sliding-window limits must be positive",
            )
            .into());
        }
        let window_start = request.reserved_at_ms.saturating_sub(limit.duration_ms);
        let mut operations = 0_u64;
        let mut signatures = 0_u64;
        for (entry_signatures, reserved_at) in &existing {
            if *reserved_at > window_start && *reserved_at <= request.reserved_at_ms {
                operations = operations.checked_add(1).ok_or_else(|| {
                    protocol(
                        ProtocolErrorCode::LimitExceededRate,
                        "rolling operation counter overflow",
                    )
                })?;
                signatures = signatures.checked_add(*entry_signatures).ok_or_else(|| {
                    protocol(
                        ProtocolErrorCode::LimitExceededRate,
                        "rolling signature counter overflow",
                    )
                })?;
            }
        }
        if operations
            .checked_add(1)
            .is_none_or(|value| value > limit.max_operations)
            || signatures
                .checked_add(request.signature_count)
                .is_none_or(|value| value > limit.max_signatures)
        {
            return Err(protocol(
                ProtocolErrorCode::LimitExceededRate,
                "exact continuous sliding-window limit exceeded",
            )
            .into());
        }
    }
    Ok(())
}

fn validate_rolling_value_limits(
    transaction: &Transaction<'_>,
    request: &ReservationRequest,
    limits: &BudgetLimits,
) -> Result<(), JournalError> {
    for limit in &limits.rolling_value_limits {
        if limit.duration_ms == 0 {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "rolling value-window duration must be positive",
            )
            .into());
        }
        let Some(requested) = request.values.get(&limit.asset_id) else {
            continue;
        };
        let window_start = request.reserved_at_ms.saturating_sub(limit.duration_ms);
        let mut statement = transaction.prepare(
            "WITH RECURSIVE lineage(approval_id) AS (
                VALUES (?1)
                UNION ALL
                SELECT metadata.renewal_of
                FROM approval_metadata metadata
                JOIN lineage ON metadata.approval_id = lineage.approval_id
                WHERE metadata.renewal_of IS NOT NULL
             )
             SELECT value.amount, reservation.reserved_at_ms
             FROM reservation_values value
             JOIN reservations reservation
               ON reservation.approval_id = value.approval_id
              AND reservation.operation_id = value.operation_id
             WHERE value.approval_id IN (SELECT approval_id FROM lineage)
               AND value.asset_id = ?2
               AND reservation.state != 'RELEASED'",
        )?;
        let rows = statement.query_map(
            params![request.approval_id.as_str(), limit.asset_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut total = BigUint::from_str(requested.as_str()).map_err(storage)?;
        for row in rows {
            let (amount, reserved_at) = row?;
            let reserved_at = reserved_at.parse::<u64>().map_err(storage)?;
            if reserved_at > window_start && reserved_at <= request.reserved_at_ms {
                total += BigUint::from_str(&amount).map_err(storage)?;
            }
        }
        if total > BigUint::from_str(limit.maximum.as_str()).map_err(storage)? {
            return Err(protocol(
                ProtocolErrorCode::LimitExceededValue,
                format!("rolling value limit exceeded for asset {}", limit.asset_id),
            )
            .into());
        }
    }
    Ok(())
}

fn approval_state_text(state: ApprovalLifecycleState) -> Result<String, JournalError> {
    json_enum_text(state)
}

fn operation_state_text(state: OperationState) -> Result<String, JournalError> {
    json_enum_text(state)
}

fn json_enum_text(value: impl Serialize) -> Result<String, JournalError> {
    serde_json::to_value(value)
        .map_err(storage)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| JournalError::Storage("enum did not serialize as a string".into()))
}

fn parse_approval_state(value: &str) -> Result<ApprovalLifecycleState, JournalError> {
    serde_json::from_value(serde_json::Value::String(value.into())).map_err(storage)
}

fn parse_operation_state(value: &str) -> Result<OperationState, JournalError> {
    serde_json::from_value(serde_json::Value::String(value.into())).map_err(storage)
}

fn valid_approval_transition(
    current: ApprovalLifecycleState,
    next: ApprovalLifecycleState,
) -> bool {
    use ApprovalLifecycleState as State;
    matches!(
        (current, next),
        (
            State::Prepared,
            State::AwaitingCeremony | State::Cancelled | State::Failed | State::Expired
        ) | (
            State::AwaitingCeremony,
            State::Active | State::Orphaned | State::Cancelled | State::Failed | State::Expired
        ) | (
            State::Orphaned,
            State::Active | State::Revoked | State::Failed
        ) | (
            State::Active,
            State::Exhausted | State::Expired | State::Revoked
        )
    )
}

fn valid_operation_transition(current: OperationState, next: OperationState) -> bool {
    use OperationState as State;
    matches!(
        (current, next),
        (
            State::Received,
            State::Validated | State::Denied | State::Cancelled | State::Failed
        ) | (
            State::Validated,
            State::Reserved | State::Denied | State::Cancelled | State::Failed
        ) | (
            State::Reserved,
            State::Dispatched | State::Denied | State::Cancelled | State::Failed
        ) | (
            State::Dispatched,
            State::DownstreamAccepted | State::Failed | State::Quarantined
        ) | (
            State::DownstreamAccepted,
            State::Committed | State::Failed | State::Quarantined
        ) | (
            State::Committed,
            State::Succeeded | State::Failed | State::Quarantined
        )
    )
}
