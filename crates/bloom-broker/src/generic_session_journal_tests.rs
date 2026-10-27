//! Real journal reservations exercise the shared token scope and its authenticated
//! evidence. Network/signing verification has separate deterministic fixtures.
use super::*;
use bloom_broker_api::*;
use ed25519_dalek::{Signer as _, Verifier as _};
use std::sync::Barrier;

struct TestAudit(ed25519_dalek::SigningKey);
impl AuditSigner for TestAudit {
    fn key_id(&self) -> Token {
        token("test-audit")
    }
    fn sign(&self, bytes: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(&self.0.sign(bytes).to_bytes()))
    }
    fn verify(&self, id: &Token, bytes: &[u8], signature: &Base64UrlBytes) -> Result<(), String> {
        if id != &self.key_id() {
            return Err("wrong key".into());
        }
        let sig: [u8; 64] = signature
            .decode()
            .try_into()
            .map_err(|_| "invalid signature")?;
        self.0
            .verifying_key()
            .verify(bytes, &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|e| e.to_string())
    }
}
fn audit() -> Arc<dyn AuditSigner> {
    Arc::new(TestAudit(ed25519_dalek::SigningKey::from_bytes(&[7; 32])))
}
fn token(s: &str) -> Token {
    Token::new(s).unwrap()
}
fn n(s: &str) -> DecimalU256 {
    DecimalU256::parse(s).unwrap()
}
fn digest(v: u8) -> Digest32 {
    Digest32::from_bytes([v; 32])
}
fn operation(v: u8) -> OperationId {
    OperationId::from_bytes([v; 32])
}
fn asset(svm: bool) -> AssetId {
    if svm {
        AssetId {
            chain: token("solana-mainnet"),
            asset: "native".into(),
        }
    } else {
        AssetId {
            chain: token("evm-137"),
            asset: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
        }
    }
}
fn template(svm: bool) -> SealedApprovalTerms {
    let class = if svm {
        "generic.solana.swap"
    } else {
        "generic.evm.swap"
    };
    SealedApprovalTerms {
        subject: ApprovalSubject::Petal {
            package_hash: digest(if svm { 2 } else { 1 }),
            route: "trade".into(),
            agent_id: None,
        },
        wallet_id: token("wallet"),
        key_ref: KeyRef {
            backend: token("local"),
            backend_instance: token("test"),
            locator: if svm { "solana" } else { "evm" }.into(),
            key_spec: if svm {
                KeySpec::Ed25519
            } else {
                KeySpec::Secp256k1
            },
            public_key_fingerprint: digest(if svm { 4 } else { 3 }),
            derivation: None,
        },
        allowed_crypto_suites: vec![if svm {
            CryptoSuite::Ed25519Message
        } else {
            CryptoSuite::Secp256k1Keccak256Recoverable
        }],
        selector: ApprovalSelector::Petal {
            package_hash: digest(if svm { 2 } else { 1 }),
            route: "trade".into(),
            allowed_operation_classes: vec![token(class)],
            route_grants: vec![],
            required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(5),
            max_signatures: DecimalU64::new(5),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(0),
        policy_version: DecimalU64::new(1),
        policy_digest: digest(5),
        provenance_digest: digest(6),
        request_nonce: RequestNonce::from_bytes([if svm { 2 } else { 1 }; 16]),
        issued_at_ms: DecimalU64::new(1),
        not_before_ms: DecimalU64::new(1),
        expires_at_ms: DecimalU64::new(10_000_000),
        renewal_of: None,
        session_budget: None,
    }
}
fn members() -> Vec<SealedApprovalTerms> {
    build_members(false)
}
fn build_members(standing: bool) -> Vec<SealedApprovalTerms> {
    let mut templates = vec![template(false), template(true)];
    if standing {
        for terms in &mut templates {
            terms.expires_at_ms = DecimalU64::new(u64::MAX);
            terms.activation_mode = ActivationMode::DurableLocal {
                provider_tier: token("local-passkey"),
                maximum_rearm_until_ms: DecimalU64::new(u64::MAX),
            };
        }
    }
    templates.sort_by_key(|t| session_member_scope_digest(t).unwrap().as_str().to_owned());
    let budget = SessionBudget {
        token_policy: Some(SessionTokenPolicy {
            schema_version: 3,
            budget_nonce: RequestNonce::from_bytes([9; 16]),
            member_scope_digests: templates
                .iter()
                .map(|t| session_member_scope_digest(t).unwrap())
                .collect(),
            member_templates: templates.clone(),
            member_backstop_allocations: templates
                .iter()
                .map(|t| SessionMemberAllocation {
                    scope_digest: session_member_scope_digest(t).unwrap(),
                    limits: t.limits.clone(),
                })
                .collect(),
            assets: vec![
                approved_session_asset(&asset(false)).unwrap(),
                approved_session_asset(&asset(true)).unwrap(),
            ],
        }),
        wallet_id: token("wallet"),
        policy_version: DecimalU64::new(1),
        policy_digest: digest(5),
        wallet_revocation_epoch: DecimalU64::new(0),
        member_keys: templates.iter().map(|t| t.key_ref.clone()).collect(),
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(10),
            max_signatures: DecimalU64::new(10),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![
                ValueLimit {
                    asset: asset(false),
                    lifetime: n("100000000"),
                    rolling_windows: vec![ValueWindow {
                        maximum: n("10000000"),
                        duration_ms: DecimalU64::new(86400000),
                    }],
                },
                ValueLimit {
                    asset: asset(true),
                    lifetime: n("1000000000"),
                    rolling_windows: vec![ValueWindow {
                        maximum: n("100000000"),
                        duration_ms: DecimalU64::new(86400000),
                    }],
                },
            ],
        },
        per_action_value_limits: vec![
            SessionValueCeiling {
                asset: asset(false),
                maximum: n("10000000"),
            },
            SessionValueCeiling {
                asset: asset(true),
                maximum: n("100000000"),
            },
        ],
        not_before_ms: DecimalU64::new(1),
        expires_at_ms: DecimalU64::new(if standing { u64::MAX } else { 10_000_000 }),
    };
    templates
        .iter_mut()
        .for_each(|t| t.session_budget = Some(budget.clone()));
    templates
}
fn prepare(j: &BrokerJournal, terms: &SealedApprovalTerms, id: u8, activate: bool) {
    terms.validate().unwrap();
    let text = serde_jcs::to_string(terms).unwrap();
    j.create_approval_record(
        &digest(id),
        &NewApprovalRecord {
            terms_jcs: &text,
            review_manifest_digest: &digest(100),
            approved_claim_digest: None,
            provenance_jcs: None,
            renewal_of: None,
        },
    )
    .unwrap();
    if activate {
        j.activate_approval_record(&digest(id), &operation(id), "{}")
            .unwrap();
    }
}
fn request(terms: &SealedApprovalTerms, id: u8, op: u8) -> ReservationRequest {
    let svm = terms.key_ref.key_spec == KeySpec::Ed25519;
    let a = asset(svm);
    let amount = if svm { "60000000" } else { "6000000" };
    ReservationRequest {
        approval_id: digest(id),
        operation_id: operation(op),
        operation_digest: digest(op),
        signature_count: 1,
        reserved_at_ms: 1_000_000,
        observed_utc_ms: Some(1_000_000),
        monotonic_anchor_ns: 1000,
        clock_boot_epoch: BootEpoch::from_bytes([1; 16]),
        values: BTreeMap::from([(format!("{}:{}", a.chain.as_str(), a.asset), n(amount))]),
    }
}
fn limits() -> BudgetLimits {
    BudgetLimits {
        max_operations: 5,
        max_signatures: 5,
        rate_limits: vec![],
        value_limits: BTreeMap::from([
            (
                format!("{}:{}", asset(false).chain.as_str(), asset(false).asset),
                n("100000000"),
            ),
            (
                format!("{}:{}", asset(true).chain.as_str(), asset(true).asset),
                n("10000000000"),
            ),
        ]),
        rolling_value_limits: vec![],
    }
}

#[test]
fn token_scope_requires_all_members_and_concurrent_assets_are_independent() {
    let journal = Arc::new(BrokerJournal::open_in_memory(audit()).unwrap());
    let m = members();
    prepare(&journal, &m[0], 1, true);
    assert!(
        journal
            .reserve_for_clock_profile(&request(&m[0], 1, 10), &limits(), false)
            .is_err()
    );
    prepare(&journal, &m[1], 2, false);
    assert!(
        journal
            .reserve_for_clock_profile(&request(&m[0], 1, 10), &limits(), false)
            .is_err()
    );
    journal
        .activate_approval_record(&digest(2), &operation(2), "{}")
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = vec![];
    for (i, member) in m.iter().enumerate() {
        let j = journal.clone();
        let b = barrier.clone();
        let r = request(member, i as u8 + 1, i as u8 + 10);
        handles.push(std::thread::spawn(move || {
            b.wait();
            j.reserve_for_clock_profile(&r, &limits(), false)
        }));
    }
    barrier.wait();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(Result::is_ok)
            .count(),
        2
    );
    journal.verify_audit_chain().unwrap();
}

#[test]
fn token_reservation_survives_restart_and_stop_fences_all_members_and_retries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.sqlite");
    let m = members();
    let r = request(&m[0], 1, 10);
    {
        let j = BrokerJournal::open(&path, audit()).unwrap();
        prepare(&j, &m[0], 1, true);
        prepare(&j, &m[1], 2, true);
        j.reserve_for_clock_profile(&r, &limits(), false).unwrap();
        j.verify_audit_chain().unwrap();
    }
    let j = BrokerJournal::open(&path, audit()).unwrap();
    j.verify_audit_chain().unwrap();
    // Stable retries return the original reservation, without charging again.
    j.reserve_for_clock_profile(&r, &limits(), false).unwrap();
    let id = m[0].session_budget.as_ref().unwrap().budget_id().unwrap();
    let stopped = j
        .stop_session_pool(&id, &operation(30), "owner stop", 1_000_001)
        .unwrap();
    assert_eq!(stopped.len(), 2);
    assert!(j.reserve_for_clock_profile(&r, &limits(), false).is_err());
    assert!(
        j.reserve_for_clock_profile(&request(&m[1], 2, 11), &limits(), false)
            .is_err()
    );
    assert_eq!(
        j.stop_session_pool(&id, &operation(30), "owner stop", 1_000_002)
            .unwrap()
            .len(),
        2
    );
    assert!(
        j.stop_session_pool(&id, &operation(30), "changed", 1_000_002)
            .is_err()
    );
    j.verify_audit_chain().unwrap();
}

#[test]
fn authenticated_token_evidence_detects_quantity_time_identity_and_budget_changes() {
    for field in [
        "signatures",
        "quantity",
        "record_time",
        "asset",
        "budget",
        "delete",
    ] {
        let j = BrokerJournal::open_in_memory(audit()).unwrap();
        let m = members();
        prepare(&j, &m[0], 1, true);
        prepare(&j, &m[1], 2, true);
        let r = request(&m[0], 1, 10);
        j.reserve_for_clock_profile(&r, &limits(), false).unwrap();
        j.verify_audit_chain().unwrap();
        {
            let connection = j.connection.lock().unwrap();
            if field == "delete" {
                connection.execute("DELETE FROM session_uses", []).unwrap();
            } else if field == "budget" {
                connection
                    .execute(
                        "UPDATE session_uses SET budget_id=?1",
                        [digest(88).as_str()],
                    )
                    .unwrap();
            } else {
                let text: String = connection
                    .query_row("SELECT record_jcs FROM session_uses", [], |row| row.get(0))
                    .unwrap();
                let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
                match field {
                    "signatures" => value["signature_count"] = serde_json::json!(9),
                    "quantity" => value["values"][0]["amount"] = serde_json::json!("1"),
                    "record_time" => value["accepted_at_ms"] = serde_json::json!(1),
                    _ => value["values"][0]["asset"]["asset"] = serde_json::json!("other"),
                }
                connection
                    .execute(
                        "UPDATE session_uses SET record_jcs=?1",
                        [serde_jcs::to_string(&value).unwrap()],
                    )
                    .unwrap();
            }
        }
        assert!(j.verify_audit_chain().is_err(), "{field}");
    }
}

#[test]
fn matching_record_and_audit_payload_forgery_cannot_reuse_cached_signed_tail() {
    let j = BrokerJournal::open_in_memory(audit()).unwrap();
    let m = members();
    prepare(&j, &m[0], 1, true);
    prepare(&j, &m[1], 2, true);
    let r = request(&m[0], 1, 10);
    j.reserve_for_clock_profile(&r, &limits(), false).unwrap();
    // Prime the verified tail before changing correlated data without changing
    // the event hash/signature. A matching digest inside forged JSON alone
    // must never count as authenticated reservation evidence.
    j.verified_audit_head().unwrap();
    {
        let connection = j.connection.lock().unwrap();
        let record: String = connection
            .query_row("SELECT record_jcs FROM session_uses", [], |row| row.get(0))
            .unwrap();
        let mut record: SessionRecordedUse = serde_json::from_str(&record).unwrap();
        record.values[0].amount = n("1");
        let text = serde_jcs::to_string(&record).unwrap();
        connection
            .execute("UPDATE session_uses SET record_jcs=?1", [&text])
            .unwrap();
        let payload: String = connection
            .query_row(
                "SELECT payload_jcs FROM audit_chain WHERE event_type='reservation.created'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        payload["session_record_digest"] =
            serde_json::to_value(session_use_record_digest(&record).unwrap()).unwrap();
        connection
            .execute(
                "UPDATE audit_chain SET payload_jcs=?1 WHERE event_type='reservation.created'",
                [serde_jcs::to_string(&payload).unwrap()],
            )
            .unwrap();
        // Exercise the runtime correlation helper directly, without obtaining
        // a newly verified tail through a full-chain scan first.
        assert!(
            verify_session_use_evidence(
                &connection,
                r.approval_id.as_str(),
                r.operation_id.as_str(),
                &text,
                Some(j.audit_signer.as_ref())
            )
            .is_err()
        );
    }
    assert!(j.session_budget_state(&r.approval_id, 1_000_001).is_err());
    assert!(
        j.reserve_for_clock_profile(&request(&m[1], 2, 11), &limits(), false)
            .is_err()
    );
    assert!(j.verify_audit_chain().is_err());
}

#[test]
fn unsigned_terminal_state_changes_cannot_release_token_capacity() {
    for initial in [
        ReservationState::Reserved,
        ReservationState::Committed,
        ReservationState::Quarantined,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state-integrity.sqlite");
        let m = members();
        let r = request(&m[0], 1, 10);
        {
            let j = BrokerJournal::open(&path, audit()).unwrap();
            prepare(&j, &m[0], 1, true);
            prepare(&j, &m[1], 2, true);
            j.reserve_for_clock_profile(&r, &limits(), false).unwrap();
            if initial != ReservationState::Reserved {
                j.finalize_reservation(&r.approval_id, &r.operation_id, initial)
                    .unwrap();
            }
            j.verify_audit_chain().unwrap();
            // Prime the authenticated head, then modify only the unsigned state row.
            j.verified_audit_head().unwrap();
            j.connection
                .lock()
                .unwrap()
                .execute("UPDATE reservations SET state='RELEASED'", [])
                .unwrap();
            assert!(
                j.session_budget_state(&r.approval_id, 1_000_001).is_err(),
                "{initial:?}"
            );
            assert!(
                j.session_budget_state(&r.approval_id, 1_000_001).is_err(),
                "{initial:?}"
            );
            assert!(
                j.reserve_for_clock_profile(&request(&m[1], 2, 11), &limits(), false)
                    .is_err(),
                "{initial:?}"
            );
        }
        let reopened = BrokerJournal::open(&path, audit()).unwrap();
        assert!(reopened.verify_audit_chain().is_err(), "{initial:?}");
        assert!(
            reopened
                .reserve_for_clock_profile(&request(&m[1], 2, 11), &limits(), false)
                .is_err(),
            "{initial:?}"
        );
    }
}

#[test]
fn authenticated_release_frees_token_capacity_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("released.sqlite");
    let m = members();
    let r = request(&m[0], 1, 10);
    {
        let j = BrokerJournal::open(&path, audit()).unwrap();
        prepare(&j, &m[0], 1, true);
        prepare(&j, &m[1], 2, true);
        j.reserve_for_clock_profile(&r, &limits(), false).unwrap();
        j.finalize_reservation(&r.approval_id, &r.operation_id, ReservationState::Released)
            .unwrap();
        j.verify_audit_chain().unwrap();
        assert!(
            j.session_budget_state(&r.approval_id, 1_000_001)
                .unwrap()
                .unwrap()
                .asset_usage
                .is_empty()
        );
    }
    let reopened = BrokerJournal::open(&path, audit()).unwrap();
    reopened.verify_audit_chain().unwrap();
    reopened
        .reserve_for_clock_profile(&request(&m[1], 2, 11), &limits(), false)
        .unwrap();
    reopened.verify_audit_chain().unwrap();
}

/// Exercise the publication paths used by service::commit_signer_result rather
/// than calling finalize_reservation directly: the next admission must accept
/// their authenticated COMMITTED state, including after restart.
#[test]
fn token_publication_preserves_audit_recovery_and_shared_capacity() {
    for (batch, signature_count) in [(false, 1usize), (true, 1), (true, 2)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("published.sqlite");
        let m = members();
        let mut reservation = request(&m[0], 1, 70);
        reservation.signature_count = signature_count as u64;
        let mut unsigned = UnsignedSignRequest {
            schema: token("bloom.sign-request/1"),
            attempt_id: digest(70),
            operation_id: reservation.operation_id.clone(),
            operation_digest: digest(0),
            attempt_digest: digest(0),
            audience: token("bloom-signer"),
            issuer_service_id: token("bloom-broker"),
            issuer_boot_epoch: BootEpoch::from_bytes([1; 16]),
            broker_signing_key_id: token("broker-test"),
            approval_id: reservation.approval_id.clone(),
            wallet_id: m[0].wallet_id.clone(),
            key_ref: serde_json::from_value(serde_json::to_value(&m[0].key_ref).unwrap()).unwrap(),
            crypto_suite: serde_json::from_value(
                serde_json::to_value(m[0].allowed_crypto_suites[0]).unwrap(),
            )
            .unwrap(),
            selector_kind: bloom_signer_api::SelectorKind::Petal,
            ordered_payload_digests: vec![digest(71); signature_count],
            ordered_hashes: vec![digest(72); signature_count],
            ordered_messages: vec![],
            signature_count: DecimalU64::new(signature_count as u64),
            petal_use_claim_digest: Some(digest(73)),
            claim_assurance_digest: Some(digest(74)),
            policy_version: m[0].policy_version.clone(),
            policy_digest: m[0].policy_digest.clone(),
            validation_receipt_digest: digest(0),
            issued_at_ms: DecimalU64::new(1_000_000),
            not_before_ms: DecimalU64::new(1_000_000),
            expires_at_ms: DecimalU64::new(1_030_000),
        };
        unsigned.operation_digest = unsigned.operation_identity().digest().unwrap();
        reservation.operation_digest = unsigned.operation_digest.clone();
        let receipt = BrokerValidationReceipt {
            approval_id: unsigned.approval_id.clone(),
            approval_digest: m[0].approval_digest().unwrap(),
            operation_digest: unsigned.operation_digest.clone(),
            policy_version: unsigned.policy_version.clone(),
            policy_digest: unsigned.policy_digest.clone(),
            claim_digest: unsigned.petal_use_claim_digest.clone(),
            assurance_digest: unsigned.claim_assurance_digest.clone(),
            reservation_ids: vec![digest(75)],
            effective_claim_assurance: None,
            broker_key_id: unsigned.broker_signing_key_id.clone(),
            broker_signature: Base64UrlBytes::from_bytes(&[7; 64]),
        };
        unsigned.validation_receipt_digest = receipt.digest().unwrap();
        unsigned.attempt_digest = unsigned.computed_attempt_digest().unwrap();
        let result = SigningResult {
            operation_id: unsigned.operation_id.clone(),
            operation_digest: unsigned.operation_digest.clone(),
            signatures: vec![
                NormalizedSignature {
                    crypto_suite: m[0].allowed_crypto_suites[0],
                    bytes: Base64UrlBytes::from_bytes(&[8; 65]),
                };
                signature_count
            ],
            signer_receipt_digest: digest(76),
            broker_receipt_digest: digest(77),
        };
        let children: Vec<_> = result
            .signatures
            .iter()
            .enumerate()
            .map(|(i, signature)| SigningResult {
                operation_id: derive_batch_child_operation_id(&result.operation_id, i).unwrap(),
                signatures: vec![signature.clone()],
                ..result.clone()
            })
            .collect();
        let publish = |j: &BrokerJournal| {
            if batch {
                j.publish_batch(&reservation.approval_id, &result, &children)
            } else {
                j.publish_result(&reservation.approval_id, &result)
            }
        };
        {
            let j = BrokerJournal::open(&path, audit()).unwrap();
            prepare(&j, &m[0], 1, true);
            prepare(&j, &m[1], 2, true);
            j.reserve_for_clock_profile(&reservation, &limits(), false)
                .unwrap();
            j.begin_sign_attempt(&unsigned, batch, &receipt).unwrap();
            for state in [
                OperationState::Validated,
                OperationState::Reserved,
                OperationState::Dispatched,
                OperationState::DownstreamAccepted,
                OperationState::Committed,
            ] {
                j.transition_operation(&result.operation_id, state).unwrap();
            }
            publish(&j).unwrap();
            j.verify_audit_chain().unwrap();
            publish(&j).unwrap(); // Idempotent publication cannot duplicate the event.
            assert_eq!(
                j.audit_entries()
                    .unwrap()
                    .iter()
                    .filter(|e| e.event_type == "reservation.finalized")
                    .count(),
                1
            );
            assert!(
                j.session_budget_state(&reservation.approval_id, 1_000_001)
                    .is_ok()
            );
        }
        let j = BrokerJournal::open(&path, audit()).unwrap();
        j.verify_audit_chain().unwrap();
        assert_eq!(
            j.operation(&result.operation_id).unwrap().unwrap().result,
            Some(result.clone())
        );
        publish(&j).unwrap();
        let mut next = request(&m[1], 2, 80);
        next.values.values_mut().for_each(|amount| {
            *amount = n(if m[1].key_ref.key_spec == KeySpec::Ed25519 {
                "60000000"
            } else {
                "6000000"
            });
        });
        j.reserve_for_clock_profile(&next, &limits(), false)
            .unwrap();
        assert!(
            j.reserve_for_clock_profile(&request(&m[1], 2, 81), &limits(), false)
                .is_err()
        );
        j.verify_audit_chain().unwrap();
    }
}

#[test]
fn same_token_allowances_are_independent_per_petal_and_account_but_routes_share_usage() {
    let j = BrokerJournal::open_in_memory(audit()).unwrap();
    let mut grants = Vec::new();
    for id in 1..=3 {
        let mut terms = template(false);
        if id == 2 {
            // another Petal on the same account
            terms.subject = ApprovalSubject::Petal {
                package_hash: digest(22),
                route: "trade".into(),
                agent_id: None,
            };
            if let ApprovalSelector::Petal { package_hash, .. } = &mut terms.selector {
                *package_hash = digest(22);
            }
        }
        if id == 3 {
            // the original Petal on another exact account
            terms.key_ref.locator = "another-account".into();
            terms.key_ref.public_key_fingerprint = digest(33);
        }
        let scope = session_member_scope_digest(&terms).unwrap();
        let mut budget = members()[0].session_budget.clone().unwrap();
        budget.member_keys = vec![terms.key_ref.clone()];
        budget.limits = terms.limits.clone();
        budget.limits.value_limits = vec![ValueLimit {
            asset: asset(false),
            lifetime: n("100000000"),
            rolling_windows: vec![ValueWindow {
                duration_ms: DecimalU64::new(86400000),
                maximum: n("10000000"),
            }],
        }];
        budget.per_action_value_limits = vec![SessionValueCeiling {
            asset: asset(false),
            maximum: n("10000000"),
        }];
        budget.token_policy = Some(SessionTokenPolicy {
            schema_version: 3,
            budget_nonce: RequestNonce::from_bytes([id; 16]),
            member_scope_digests: vec![scope.clone()],
            member_templates: vec![terms.clone()],
            member_backstop_allocations: vec![SessionMemberAllocation {
                scope_digest: scope,
                limits: terms.limits.clone(),
            }],
            assets: vec![approved_session_asset(&asset(false)).unwrap()],
        });
        terms.session_budget = Some(budget);
        prepare(&j, &terms, id, true);
        j.reserve_for_clock_profile(&request(&terms, id, id + 20), &limits(), false)
            .unwrap();
        grants.push(terms);
    }
    for (index, terms) in grants.iter().enumerate() {
        let id = index as u8 + 1;
        assert!(
            j.reserve_for_clock_profile(&request(terms, id, id + 40), &limits(), false)
                .is_err()
        );
        // Route selection never creates another ledger: every use binds the
        // same owner-reviewed budget identity and counts toward its window.
        let usage = j
            .session_budget_state(&digest(id), 1_000_001)
            .unwrap()
            .unwrap();
        assert_eq!(usage.asset_usage[0].amount, n("6000000"));
    }
    j.verify_audit_chain().unwrap();
}

#[test]
fn rearming_standing_authority_preserves_usage_and_cannot_bypass_a_stopped_budget() {
    let j = BrokerJournal::open_in_memory(audit()).unwrap();
    let m = build_members(true);
    prepare(&j, &m[0], 1, true);
    prepare(&j, &m[1], 2, true);
    j.reserve_for_clock_profile(&request(&m[0], 1, 10), &limits(), false)
        .unwrap();
    let before = j.session_budget_state(&digest(1), 1_000_001).unwrap();
    let counters = j.approval_limit_state(&digest(1)).unwrap();
    j.prepare_standing_rearm(&digest(1), &digest(99)).unwrap();
    j.activate_approval_record(&digest(1), &operation(99), "{}")
        .unwrap();
    assert_eq!(
        before,
        j.session_budget_state(&digest(1), 1_000_001).unwrap()
    );
    assert_eq!(counters, j.approval_limit_state(&digest(1)).unwrap());
    j.verify_audit_chain().unwrap();
    let id = m[0].session_budget.as_ref().unwrap().budget_id().unwrap();
    j.stop_session_pool(&id, &operation(98), "owner stop", 1_000_002)
        .unwrap();
    assert!(j.prepare_standing_rearm(&digest(1), &digest(97)).is_err());
}
