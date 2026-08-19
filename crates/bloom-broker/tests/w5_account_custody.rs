//! W5 account custody over the real Broker↔Signer transport: Machine-edge
//! allocate/retire ceremonies with exact-terms binding, the wallet.accounts
//! projection, replay/cancel/restart behavior, fail-closed paths, the
//! two-passkey + recovery same-root proof, and a Broker-side secret scan.

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use bloom_broker::{
    authority::{AssuranceRegistry, BrokerAuthority},
    ceremony::CeremonyBroker,
    clock::BrokerClock,
    journal::{AuditSigner, BrokerJournal},
    service::BrokerRpcService,
    signer_client::BrokerSignerClient,
};
use bloom_broker_api::{
    AccountTerms, ActivationMode, AddressEncoding, ApprovalLimits, ApprovalSelector,
    ApprovalSubject, Base64UrlBytes, BootEpoch, CeremonyKind, CeremonyState, CryptoSuite,
    DecimalU64, DerivationProfile, DerivedAccountRequest, Digest32, IdRequest, KeyRef, KeySpec,
    MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, MachineSignRequest,
    OperationId, OperationRequest, PROVENANCE_RECORD_SIGNATURE_DOMAIN, ProvenanceOperationClass,
    ProvenanceRecord, ProvenanceSubject, RequestNonce, SealedApprovalTerms, SigningPayloads, Token,
    WalletAccountsPublic, WalletPublic, WalletRequest, WalletSeedProfile,
};
use bloom_broker_debug_driver::{VirtualAuthenticator, seal_hpke};
use bloom_signer::{
    ceremony::SignerCeremonyService,
    clock::SignerClock,
    engine::{SignerAuditKeys, SignerEngine},
    hpke::{CUSTODY_OUTPUT_INFO, HpkeRecipient, LOCAL_PRF_INFO},
    registry::BackendRegistry,
    service::SignerRpcService,
};
use bloom_signer_api::{
    BrokerSignerRequest, BrokerSignerResponse, BrokerSignerService, CeremonyChallenge,
    CustodyHpkeAad, CustodyOutputHpkeAad, CustodySignerContribution, LocalPrfHpkeAad,
    SignedJournalHead, SignerCeremonyContribution,
};
use bloom_triad_local_transport::{EndpointQuota, JournalExchange, LocalIdentity, PeerAcl};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use k256::pkcs8::EncodePublicKey as _;
use sha2::Digest as _;
use sha2::Sha256;
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt as _, path::Path, sync::Arc};
use tower::ServiceExt as _;

fn test_time_source() -> &'static str {
    #[cfg(target_os = "linux")]
    return "linux-chrony-nts";
    #[cfg(target_os = "macos")]
    return "macos-managed-timed";
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    panic!("W5 ceremony tests require a reviewed trusted-time platform");
}

fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

fn signer_audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: Token::new("signer-audit-key").unwrap(),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

fn local_identity(service_id: &str, seed: [u8; 32], epoch: &str) -> LocalIdentity {
    LocalIdentity {
        service_id: Token::new(service_id).unwrap(),
        boot_epoch: BootEpoch::new(epoch.repeat(16)).unwrap(),
        application_key_id: Token::new(format!("{service_id}-app")).unwrap(),
        signing_key: Arc::new(SigningKey::from_bytes(&seed)),
    }
}

fn peer_acl(identity: &LocalIdentity, effective_uid: u32) -> PeerAcl {
    PeerAcl {
        effective_uid,
        service_id: identity.service_id.clone(),
        boot_epoch: identity.boot_epoch.clone(),
        application_key_id: identity.application_key_id.clone(),
        application_public_key: identity.signing_key.verifying_key().to_bytes(),
    }
}

struct ServiceTestAuditSigner;

impl AuditSigner for ServiceTestAuditSigner {
    fn key_id(&self) -> Token {
        Token::new("broker-audit-key").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(&sha2::Sha256::digest(message)))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id == &self.key_id()
            && signature.decode() == sha2::Sha256::digest(message).as_slice()
        {
            Ok(())
        } else {
            Err("audit signature mismatch".into())
        }
    }
}

struct SignerJournalExchange(Arc<SignerEngine>);

impl JournalExchange<bloom_signer_api::ProtocolError> for SignerJournalExchange {
    fn checkpoint_request_head(
        &self,
        _method: &Token,
        _peer_head: &SignedJournalHead,
    ) -> Result<(), bloom_signer_api::ProtocolError> {
        Ok(())
    }

    fn local_journal_head(
        &self,
        _method: &Token,
    ) -> Result<(u64, Digest32), bloom_signer_api::ProtocolError> {
        self.0.verified_audit_head()
    }
}

struct AcceptingCheckpointSink;

impl bloom_audit_checkpoint::CheckpointSink for AcceptingCheckpointSink {
    fn append_peer_head(
        &self,
        _peer_head: &SignedJournalHead,
    ) -> Result<bloom_audit_checkpoint::AppendOutcome, bloom_audit_checkpoint::CheckpointError>
    {
        Ok(bloom_audit_checkpoint::AppendOutcome::Appended)
    }
}

/// A live Broker↔Signer stack on real sqlite stores over an authenticated
/// Unix socket. Reopening the same root directory rebuilds both services
/// from disk for restart proofs.
static STACK_SEQUENCE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

struct AccountStack {
    broker: Arc<BrokerRpcService>,
    signer_engine: Arc<SignerEngine>,
    signer_ceremony: Arc<SignerCeremonyService>,
    authority: Arc<bloom_broker::authority::BrokerAuthority>,
    signer_server: tokio::task::JoinHandle<()>,
    prefix: u8,
    counter: u8,
}

impl AccountStack {
    fn next_operation(&mut self) -> OperationId {
        self.counter = self.counter.checked_add(1).expect("operation budget");
        OperationId::new(format!("{:02x}{:02x}", self.prefix, self.counter).repeat(16)).unwrap()
    }
}

impl Drop for AccountStack {
    fn drop(&mut self) {
        self.signer_server.abort();
    }
}

async fn account_stack(root: &Path, tag: &str) -> AccountStack {
    account_stack_with_backup(root, tag, None).await
}

async fn account_stack_with_backup(
    root: &Path,
    tag: &str,
    backup: Option<&bloom_signer::engine::SignerBackupSet>,
) -> AccountStack {
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    let signer_engine = Arc::new(
        SignerEngine::open(
            root.join("signer.sqlite"),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            signer_audit_keys(),
            registry,
        )
        .unwrap(),
    );
    if let Some(backup) = backup {
        signer_engine
            .restore_backup(backup)
            .expect("restore the exported Signer backup");
    }
    let signer_ceremony = Arc::new(
        SignerCeremonyService::new(
            signer_engine.clone(),
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    let effective_uid = fs::metadata(root).unwrap().uid();
    let signer_identity = local_identity("bloom-signer", [0x32; 32], "32");
    let broker_identity = local_identity("bloom-broker", [0x31; 32], "31");
    let signer_acl = peer_acl(&signer_identity, effective_uid);
    let broker_acl = peer_acl(&broker_identity, effective_uid);
    let socket_path = root.join(format!("signer-{tag}.sock"));
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let signer_rpc = Arc::new(SignerRpcService::new(
        signer_engine.clone(),
        signer_ceremony.clone(),
        Arc::new(
            SignerClock::new(
                signer_engine.clone(),
                test_time_source(),
                signer_identity.boot_epoch.clone(),
            )
            .unwrap(),
        ),
        signer_identity.boot_epoch.clone(),
        digest("e2"),
        "test",
    ));
    let server_identity = signer_identity.clone();
    let server_rpc = signer_rpc.clone();
    let server_acl = broker_acl.clone();
    let exchange = SignerJournalExchange(signer_engine.clone());
    let signer_server = tokio::spawn(async move {
        let quota = EndpointQuota::new(16, 1_000, 60_000, 1_000, 60_000).unwrap();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            bloom_triad_local_transport::dispatch_connection_with_journal_heads::<
                BrokerSignerRequest,
                BrokerSignerResponse,
                bloom_signer_api::ProtocolError,
                _,
                _,
            >(
                &mut stream,
                &server_identity,
                &server_acl,
                bloom_signer_api::SIGNER_API_CURRENT,
                bloom_signer_api::SIGNER_API_RANGE,
                &quota,
                &exchange,
                |request| BrokerSignerService::dispatch(server_rpc.as_ref(), request),
            )
            .await
            .unwrap();
        }
    });
    let journal = Arc::new(
        BrokerJournal::open(
            root.join("broker-journal.sqlite"),
            Arc::new(ServiceTestAuditSigner),
        )
        .unwrap(),
    );
    let signer_client = BrokerSignerClient::connect_unix(
        &socket_path,
        broker_identity.clone(),
        signer_acl.clone(),
        journal.clone(),
        Arc::new(AcceptingCheckpointSink),
    )
    .unwrap();
    let authority = Arc::new(
        BrokerAuthority::open(
            root.join("broker-authority.sqlite"),
            journal.clone(),
            BTreeMap::new(),
            Token::new("installer-key").unwrap(),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            AssuranceRegistry::compiled(Vec::new()).unwrap(),
        )
        .unwrap(),
    );
    let ceremony = CeremonyBroker::open_with_manifest_signer(
        root.join("ceremony.sqlite"),
        Arc::new(signer_client.clone()),
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        journal.clone(),
    )
    .unwrap();
    let broker = Arc::new(
        BrokerRpcService::new(
            authority.clone(),
            journal.clone(),
            Arc::new(
                BrokerClock::new(
                    journal.clone(),
                    test_time_source(),
                    broker_identity.boot_epoch.clone(),
                )
                .unwrap(),
            ),
            ceremony,
            signer_client.clone(),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]),
            broker_identity.boot_epoch.clone(),
            digest("e3"),
            "test",
        )
        .unwrap(),
    );
    AccountStack {
        broker,
        signer_engine,
        signer_ceremony,
        authority,
        signer_server,
        prefix: STACK_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        counter: 0,
    }
}

fn url_token(url: &str) -> String {
    url.strip_prefix("http://localhost:18734/ceremony/")
        .unwrap()
        .to_owned()
}

async fn get_session(
    broker: &BrokerRpcService,
    ceremony_id: &str,
    token: &str,
) -> serde_json::Value {
    let response = broker
        .ceremony()
        .router()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{ceremony_id}"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn post_complete(
    broker: &BrokerRpcService,
    ceremony_id: &str,
    token: &str,
    body: serde_json::Value,
) -> StatusCode {
    let response = broker
        .ceremony()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() != StatusCode::OK {
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        panic!(
            "complete returned {}: {}",
            parts.status,
            String::from_utf8_lossy(&bytes)
        );
    }
    response.status()
}

async fn custody_result(
    stack: &AccountStack,
    operation_id: &OperationId,
) -> bloom_broker_api::CustodyResult {
    match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::CustodyResult(OperationRequest {
            operation_id: operation_id.clone(),
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::CustodyResult(result) => result,
        response => panic!("unexpected custody result: {response:?}"),
    }
}

/// Translate a north encrypted browser result into the south HPKE envelope
/// the test recipient opens.
fn south_envelope(
    encrypted: &bloom_broker_api::EncryptedBrowserResult,
) -> bloom_signer_api::HpkeEnvelope {
    bloom_signer_api::HpkeEnvelope {
        kem_output: encrypted.kem_output.clone(),
        ciphertext: encrypted.ciphertext.clone(),
    }
}

async fn wallet_accounts(stack: &AccountStack, wallet_id: &Token) -> WalletAccountsPublic {
    match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::WalletAccounts(WalletRequest {
            wallet_id: wallet_id.clone(),
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::WalletAccounts(accounts) => accounts,
        response => panic!("unexpected wallet accounts: {response:?}"),
    }
}

async fn wallet_public(stack: &AccountStack, wallet_id: &Token) -> WalletPublic {
    match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::WalletGetPublic(WalletRequest {
            wallet_id: wallet_id.clone(),
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::WalletGetPublic(wallet) => wallet,
        response => panic!("unexpected wallet public: {response:?}"),
    }
}

fn now_plus(seconds: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + seconds * 1_000
}

/// Register a fresh wallet through the Machine edge. Omitting the seed
/// profile selects the BIP-39 multi-curve root; registration allocates the
/// canonical initial EVM account. Returns the custody result and the signer
/// contribution (needed to open the sealed recovery factor).
async fn register_bip39_wallet(
    stack: &mut AccountStack,
    wallet_id: &Token,
    authenticator: &VirtualAuthenticator,
    output_recipient: Option<&HpkeRecipient>,
) -> (bloom_broker_api::CustodyResult, CustodySignerContribution) {
    let operation_id = stack.next_operation();
    let request = custody_request(
        CeremonyKind::WalletRegistration,
        operation_id.clone(),
        Some(wallet_id.clone()),
        None,
        digest("61"),
        Token::new("passkey-prf").unwrap(),
    );
    let prepared = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::WalletRegistrationPrepare(request),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::WalletRegistrationPrepare(prepared) => prepared,
        response => panic!("unexpected registration response: {response:?}"),
    };
    let ceremony_id = stack
        .broker
        .ceremony()
        .public_status(&operation_id)
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&prepared.ceremony_url);
    let session = get_session(stack.broker.as_ref(), &ceremony_id, &token).await;
    let mut first: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let mut second: CeremonyChallenge =
        serde_json::from_value(session["challenges"][1]["binding"].clone()).unwrap();
    let mut contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    // Bind the recovery-output recipient through the authenticated browser
    // session (the prepare request itself never carries the key).
    if let Some(recipient) = output_recipient {
        let bound = stack
            .broker
            .ceremony()
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/session/{ceremony_id}/output-key"))
                    .header(header::HOST, "localhost:18734")
                    .header(header::ORIGIN, "http://localhost:18734")
                    .header("x-bloom-ceremony-token", &token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "recipient_key": recipient.public_key()
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bound.status(), StatusCode::OK);
        let projection: serde_json::Value =
            serde_json::from_slice(&bound.into_body().collect().await.unwrap().to_bytes()).unwrap();
        contribution = serde_json::from_value(projection["signer_contribution"].clone()).unwrap();
        first = serde_json::from_value(projection["challenges"][0]["binding"].clone()).unwrap();
        second = serde_json::from_value(projection["challenges"][1]["binding"].clone()).unwrap();
        assert_eq!(
            contribution.browser_output_recipient_key.as_ref(),
            Some(recipient.public_key())
        );
    }
    let attestation = authenticator.attestation(&first.canonical_bytes().unwrap());
    let assertion = authenticator.assertion(&second.canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: bloom_signer_api::CeremonyKind::WalletRegistration,
        custody_operation_id: operation_id.clone(),
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("passkey-prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let prf = authenticator.deterministic_prf();
    let encrypted_input = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &prf,
    )
    .unwrap();
    let status = post_complete(
        stack.broker.as_ref(),
        &ceremony_id,
        &token,
        serde_json::json!({
            "proof": {
                "kind": "registration",
                "attestation": attestation,
                "prf_assertion": assertion
            },
            "encrypted_input": encrypted_input,
            "public_binding_digest": digest("61")
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // A registration that returns a sealed recovery factor parks in
    // AwaitingRecoveryAck until the browser acknowledges receipt.
    if output_recipient.is_some() {
        let ack = stack
            .broker
            .ceremony()
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/session/{ceremony_id}/ack"))
                    .header(header::HOST, "localhost:18734")
                    .header(header::ORIGIN, "http://localhost:18734")
                    .header("x-bloom-ceremony-token", &token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ack.status(), StatusCode::NO_CONTENT);
    }
    (custody_result(stack, &operation_id).await, contribution)
}

fn custody_request(
    kind: CeremonyKind,
    operation_id: OperationId,
    wallet_id: Option<Token>,
    key_ref: Option<bloom_broker_api::KeyRef>,
    terms_digest: Digest32,
    input_class: Token,
) -> bloom_broker_api::CustodyPrepareRequest {
    bloom_broker_api::CustodyPrepareRequest {
        ceremony_kind: kind,
        custody_operation_id: operation_id,
        wallet_id,
        key_ref,
        exact_terms_digest: terms_digest,
        expected_input_class: input_class,
        browser_output_recipient_key: None,
        petal_key_scope: None,
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_request: None,
        account_terms: None,
    }
}

/// Complete a generic (assertion-only) custody ceremony — allocate, retire,
/// and friends — authenticated by the given passkey.
async fn complete_generic_ceremony(
    stack: &AccountStack,
    request: &bloom_broker_api::CustodyPrepareRequest,
    prepared: &bloom_broker_api::CustodyPrepareResponse,
    authenticator: &VirtualAuthenticator,
    sign_count: u32,
) -> bloom_broker_api::CustodyResult {
    let ceremony_id = stack
        .broker
        .ceremony()
        .public_status(&request.custody_operation_id)
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&prepared.ceremony_url);
    let session = get_session(stack.broker.as_ref(), &ceremony_id, &token).await;
    let challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let assertion = authenticator.assertion(&challenge.canonical_bytes().unwrap(), sign_count);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: south_ceremony_kind(request.ceremony_kind),
        custody_operation_id: request.custody_operation_id.clone(),
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: contribution.wallet_id.clone(),
        key_ref: contribution.key_ref.clone(),
        credential_id: Some(assertion.credential_id.clone()),
        expected_input_class: request.expected_input_class.clone(),
    }
    .canonical_bytes()
    .unwrap();
    let input = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "effect": {"kind": effect_kind(request.ceremony_kind)}
    }))
    .unwrap();
    let encrypted_input = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &input,
    )
    .unwrap();
    let status = post_complete(
        stack.broker.as_ref(),
        &ceremony_id,
        &token,
        serde_json::json!({
            "proof": {"kind": "assertion", "assertion": assertion},
            "encrypted_input": encrypted_input,
            "public_binding_digest": request.exact_terms_digest
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    custody_result(stack, &request.custody_operation_id).await
}

fn effect_kind(kind: CeremonyKind) -> &'static str {
    match kind {
        CeremonyKind::AccountAllocate => "account_allocate",
        CeremonyKind::AccountRetire => "account_retire",
        other => panic!("unsupported generic ceremony {other:?}"),
    }
}

fn south_ceremony_kind(kind: CeremonyKind) -> bloom_signer_api::CeremonyKind {
    match kind {
        CeremonyKind::WalletRegistration => bloom_signer_api::CeremonyKind::WalletRegistration,
        CeremonyKind::WalletImport => bloom_signer_api::CeremonyKind::WalletImport,
        CeremonyKind::WalletExport => bloom_signer_api::CeremonyKind::WalletExport,
        CeremonyKind::WalletDelete => bloom_signer_api::CeremonyKind::WalletDelete,
        CeremonyKind::WalletRecovery => bloom_signer_api::CeremonyKind::WalletRecovery,
        CeremonyKind::CredentialAdd => bloom_signer_api::CeremonyKind::CredentialAdd,
        CeremonyKind::CredentialReplace => bloom_signer_api::CeremonyKind::CredentialReplace,
        CeremonyKind::CredentialRemove => bloom_signer_api::CeremonyKind::CredentialRemove,
        CeremonyKind::BackendEnrollment => bloom_signer_api::CeremonyKind::BackendEnrollment,
        CeremonyKind::KeyDerive => bloom_signer_api::CeremonyKind::KeyDerive,
        CeremonyKind::AccountAllocate => bloom_signer_api::CeremonyKind::AccountAllocate,
        CeremonyKind::AccountRetire => bloom_signer_api::CeremonyKind::AccountRetire,
        CeremonyKind::PolicyUpdate => bloom_signer_api::CeremonyKind::PolicyUpdate,
        CeremonyKind::SealedApproval => bloom_signer_api::CeremonyKind::SealedApproval,
    }
}

fn solana_derivation_request() -> DerivedAccountRequest {
    DerivedAccountRequest {
        derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
        requested_role: Token::new("solana-account").unwrap(),
        account: Some(0),
    }
}

/// Build the exact allocation terms a Machine client constructs from the
/// wallet's live public projection.
fn allocation_terms(
    wallet: &WalletPublic,
    derivation: DerivedAccountRequest,
    replay_id: OperationId,
) -> AccountTerms {
    let profile = derivation.derivation_profile;
    AccountTerms {
        schema: Token::new("bloom.account_terms.v1").unwrap(),
        wallet_id: wallet.wallet_id.clone(),
        seed_profile: WalletSeedProfile::Bip39MulticurveV1,
        derivation: Some(derivation),
        retire_key_fingerprint: None,
        path_template: profile.path_template().to_owned(),
        key_spec: profile.key_spec(),
        allowed_crypto_suites: profile.frozen_crypto_suites().to_vec(),
        policy_version: wallet.policy_version.clone(),
        revocation_epoch: wallet.wallet_revocation_epoch.clone(),
        replay_id,
        expires_at_ms: DecimalU64::new(now_plus(600)),
        audit_purpose: Token::new("allocate-derived-account").unwrap(),
    }
}

fn allocate_request(
    wallet_id: &Token,
    terms: AccountTerms,
) -> bloom_broker_api::CustodyPrepareRequest {
    let mut request = custody_request(
        CeremonyKind::AccountAllocate,
        terms.replay_id.clone(),
        Some(wallet_id.clone()),
        None,
        terms.request_digest().unwrap(),
        Token::new("generic-custody-v1").unwrap(),
    );
    request.derivation_request = terms.derivation.clone();
    request.account_terms = Some(terms);
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_allocate_retire_replay_cancel_restart_over_real_transport() {
    let directory = tempfile::tempdir().unwrap();
    let mut stack = account_stack(directory.path(), "a1").await;
    let authenticator = VirtualAuthenticator::generate();
    let wallet_id = Token::new("quiet-lilac").unwrap();

    // Registration with no explicit seed profile selects bip39 and
    // allocates the canonical initial EVM account m/44'/60'/0'/0/0.
    let (registration, _) =
        register_bip39_wallet(&mut stack, &wallet_id, &authenticator, None).await;
    assert_eq!(registration.public_key_refs.len(), 1);
    assert!(matches!(
        registration.public_key_refs[0].derivation,
        Some(bloom_broker_api::DerivationRef::Bip39Multicurve { .. })
    ));

    let public = wallet_public(&stack, &wallet_id).await;
    let accounts = wallet_accounts(&stack, &wallet_id).await;
    assert_eq!(accounts.seed_profile, WalletSeedProfile::Bip39MulticurveV1);
    assert_eq!(accounts.accounts.len(), 1);
    let initial = &accounts.accounts[0];
    assert_eq!(initial.path, "m/44'/60'/0'/0/0");
    assert_eq!(initial.chain_projections.len(), 1);
    let evm_projection = &initial.chain_projections[0];
    assert_eq!(evm_projection.chain_family.as_str(), "evm");
    assert_eq!(evm_projection.caip2, "eip155:1");
    assert_eq!(evm_projection.address_encoding, AddressEncoding::Hex0x);
    assert_eq!(
        evm_projection.caip10,
        format!("eip155:1:{}", evm_projection.address)
    );
    assert_eq!(evm_projection.address.len(), 42);

    // Allocate the Solana sibling with full exact terms.
    let allocate_operation = stack.next_operation();
    let terms = allocation_terms(
        &public,
        solana_derivation_request(),
        allocate_operation.clone(),
    );
    let request = allocate_request(&wallet_id, terms);
    let prepared = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::AccountAllocatePrepare(request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::AccountAllocatePrepare(prepared) => prepared,
        response => panic!("unexpected allocate response: {response:?}"),
    };

    // Replaying the identical prepare returns the identical ceremony.
    let replayed = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::AccountAllocatePrepare(request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::AccountAllocatePrepare(prepared) => prepared,
        response => panic!("unexpected replay response: {response:?}"),
    };
    assert_eq!(replayed.ceremony_url, prepared.ceremony_url);

    let allocate_result =
        complete_generic_ceremony(&stack, &request, &prepared, &authenticator, 2).await;
    assert_eq!(allocate_result.public_key_refs.len(), 1);
    assert_eq!(
        allocate_result.public_key_refs[0].key_spec,
        bloom_broker_api::KeySpec::Ed25519
    );

    let accounts_after = wallet_accounts(&stack, &wallet_id).await;
    assert_eq!(accounts_after.accounts.len(), 2);
    let solana_account = accounts_after
        .accounts
        .iter()
        .find(|account| account.derivation_profile == DerivationProfile::Bip44SolanaSlip10Ed25519V1)
        .expect("solana account is projected");
    assert_eq!(solana_account.path, "m/44'/501'/0'/0'");
    assert_eq!(solana_account.key_ref, allocate_result.public_key_refs[0]);
    let solana_projection = &solana_account.chain_projections[0];
    assert_eq!(solana_projection.chain_family.as_str(), "solana");
    assert_eq!(
        solana_projection.caip2,
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    );
    assert_eq!(solana_projection.address_encoding, AddressEncoding::Base58);
    assert_eq!(
        solana_projection.caip10,
        format!(
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:{}",
            solana_projection.address
        )
    );

    // A cancelled allocation adds nothing.
    let cancel_operation = stack.next_operation();
    let cancel_terms = allocation_terms(
        &public,
        DerivedAccountRequest {
            derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
            requested_role: Token::new("secondary-evm").unwrap(),
            account: Some(1),
        },
        cancel_operation.clone(),
    );
    match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::AccountAllocatePrepare(allocate_request(&wallet_id, cancel_terms)),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::AccountAllocatePrepare(_) => {}
        response => panic!("unexpected cancel-prepare response: {response:?}"),
    }
    let cancelled = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::CeremonyCancel(IdRequest {
            id: Digest32::new(cancel_operation.as_str().to_owned()).unwrap(),
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::CeremonyCancel(status) => status,
        response => panic!("unexpected cancel response: {response:?}"),
    };
    assert_ne!(cancelled.state, CeremonyState::Succeeded);
    assert_eq!(
        wallet_accounts(&stack, &wallet_id).await.accounts.len(),
        2,
        "a cancelled allocation must not add an account"
    );

    // Restart both services from disk: the projection is byte-identical.
    let before_restart = serde_jcs::to_string(&wallet_accounts(&stack, &wallet_id).await).unwrap();
    drop(stack);
    let mut restarted = account_stack(directory.path(), "a2").await;
    let after_restart =
        serde_jcs::to_string(&wallet_accounts(&restarted, &wallet_id).await).unwrap();
    assert_eq!(before_restart, after_restart);

    // Retire the Solana child through an exact-terms ceremony.
    let retire_operation = restarted.next_operation();
    let public_after = wallet_public(&restarted, &wallet_id).await;
    let fingerprint = solana_account.public_key_fingerprint.clone();
    let retire_terms = AccountTerms {
        schema: Token::new("bloom.account_terms.v1").unwrap(),
        wallet_id: wallet_id.clone(),
        seed_profile: WalletSeedProfile::Bip39MulticurveV1,
        derivation: None,
        retire_key_fingerprint: Some(fingerprint),
        path_template: DerivationProfile::Bip44SolanaSlip10Ed25519V1
            .path_template()
            .to_owned(),
        key_spec: KeySpec::Ed25519,
        allowed_crypto_suites: DerivationProfile::Bip44SolanaSlip10Ed25519V1
            .frozen_crypto_suites()
            .to_vec(),
        policy_version: public_after.policy_version.clone(),
        revocation_epoch: public_after.wallet_revocation_epoch.clone(),
        replay_id: retire_operation.clone(),
        expires_at_ms: DecimalU64::new(now_plus(600)),
        audit_purpose: Token::new("retire-derived-account").unwrap(),
    };
    let mut retire_request = custody_request(
        CeremonyKind::AccountRetire,
        retire_operation.clone(),
        Some(wallet_id.clone()),
        Some(solana_account.key_ref.clone()),
        retire_terms.request_digest().unwrap(),
        Token::new("generic-custody-v1").unwrap(),
    );
    retire_request.account_terms = Some(retire_terms);
    let retire_prepared = match MachineBrokerService::dispatch(
        restarted.broker.as_ref(),
        MachineBrokerRequest::AccountRetirePrepare(retire_request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::AccountRetirePrepare(prepared) => prepared,
        response => panic!("unexpected retire response: {response:?}"),
    };
    let retire_result = complete_generic_ceremony(
        &restarted,
        &retire_request,
        &retire_prepared,
        &authenticator,
        3,
    )
    .await;
    assert!(retire_result.public_key_refs.is_empty());
    let accounts_after_retire = wallet_accounts(&restarted, &wallet_id).await;
    assert_eq!(
        accounts_after_retire.accounts.len(),
        1,
        "retired accounts leave the projection"
    );
    assert_eq!(
        accounts_after_retire.accounts[0].derivation_profile,
        DerivationProfile::Bip44EvmSecp256k1V1
    );

    // Retiring the same child twice fails closed: it is no longer active.
    let second_retire = restarted.next_operation();
    let mut second_terms = retire_request.account_terms.clone().unwrap();
    second_terms.replay_id = second_retire.clone();
    second_terms.policy_version = public_after.policy_version.clone();
    let mut second_request = custody_request(
        CeremonyKind::AccountRetire,
        second_retire.clone(),
        Some(wallet_id.clone()),
        Some(solana_account.key_ref.clone()),
        second_terms.request_digest().unwrap(),
        Token::new("generic-custody-v1").unwrap(),
    );
    second_request.account_terms = Some(second_terms);
    let error = MachineBrokerService::dispatch(
        restarted.broker.as_ref(),
        MachineBrokerRequest::AccountRetirePrepare(second_request),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.code,
        bloom_broker_api::ProtocolErrorCode::KeyrefMismatch
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_passkeys_and_recovery_unlock_the_same_bip39_root_over_real_transport() {
    let directory = tempfile::tempdir().unwrap();
    let mut stack = account_stack(directory.path(), "r1").await;
    let passkey_a = VirtualAuthenticator::generate();
    let passkey_b = VirtualAuthenticator::generate();
    let recovery_credential = VirtualAuthenticator::generate();
    let wallet_id = Token::new("folded-root").unwrap();

    // Register with an output recipient so the sealed recovery factor comes
    // back to the browser.
    let output_recipient = HpkeRecipient::generate();
    let (registration, registration_contribution) =
        register_bip39_wallet(&mut stack, &wallet_id, &passkey_a, Some(&output_recipient)).await;
    let initial_accounts = wallet_accounts(&stack, &wallet_id).await;
    assert_eq!(initial_accounts.accounts.len(), 1);
    let initial_evm = initial_accounts.accounts[0].clone();

    let recovery_plaintext = output_recipient
        .open(
            &south_envelope(registration.encrypted_browser_result.as_ref().unwrap()),
            CUSTODY_OUTPUT_INFO,
            &CustodyOutputHpkeAad {
                ceremony_id: registration_contribution.ceremony_id.clone(),
                ceremony_kind: bloom_signer_api::CeremonyKind::WalletRegistration,
                custody_operation_id: registration.custody_operation_id.clone(),
                signer_contribution_digest: registration_contribution.digest().unwrap(),
                public_binding_digest: digest("61"),
            }
            .canonical_bytes()
            .unwrap(),
        )
        .unwrap();
    let recovery: serde_json::Value =
        serde_json::from_slice(recovery_plaintext.expose_to_backend()).unwrap();
    assert!(recovery.get("recovery_id").is_some());
    assert!(recovery.get("recovery_secret").is_some());

    // Add a second passkey authorized by the first.
    let add_operation = stack.next_operation();
    let add_request = custody_request(
        CeremonyKind::CredentialAdd,
        add_operation.clone(),
        Some(wallet_id.clone()),
        None,
        digest("71"),
        Token::new("credential-change-v1").unwrap(),
    );
    let add_prepared = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::CredentialAddPrepare(add_request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::CredentialAddPrepare(prepared) => prepared,
        response => panic!("unexpected credential add response: {response:?}"),
    };
    let ceremony_id = stack
        .broker
        .ceremony()
        .public_status(&add_operation)
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&add_prepared.ceremony_url);
    let session = get_session(stack.broker.as_ref(), &ceremony_id, &token).await;
    let authority_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let attestation_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][1]["binding"].clone()).unwrap();
    let prf_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][2]["binding"].clone()).unwrap();
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let authority_assertion =
        passkey_a.assertion(&authority_challenge.canonical_bytes().unwrap(), 2);
    let new_attestation = passkey_b.attestation(&attestation_challenge.canonical_bytes().unwrap());
    let new_prf_assertion = passkey_b.assertion(&prf_challenge.canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: bloom_signer_api::CeremonyKind::CredentialAdd,
        custody_operation_id: add_operation.clone(),
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(new_attestation.credential_id.clone()),
        expected_input_class: Token::new("credential-change-v1").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let change_input = serde_jcs::to_vec(&serde_json::json!({
        "authority_prf": Base64UrlBytes::from_bytes(&passkey_a.deterministic_prf()),
        "new_credential_prf": Base64UrlBytes::from_bytes(&passkey_b.deterministic_prf()),
    }))
    .unwrap();
    let encrypted_input = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &change_input,
    )
    .unwrap();
    let status = post_complete(
        stack.broker.as_ref(),
        &ceremony_id,
        &token,
        serde_json::json!({
            "proof": {
                "kind": "authority_credential_change",
                "authority_assertion": authority_assertion,
                "new_credential_attestation": new_attestation,
                "new_credential_prf_assertion": new_prf_assertion
            },
            "encrypted_input": encrypted_input,
            "public_binding_digest": digest("71")
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Allocate the Solana child authenticated ONLY by the second passkey:
    // its PRF must unwrap the same WKEK, so the same root drives the
    // derivation.
    let public = wallet_public(&stack, &wallet_id).await;
    let allocate_operation = stack.next_operation();
    let terms = allocation_terms(
        &public,
        solana_derivation_request(),
        allocate_operation.clone(),
    );
    let allocate_with_b = allocate_request(&wallet_id, terms);
    let prepared_b = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::AccountAllocatePrepare(allocate_with_b.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::AccountAllocatePrepare(prepared) => prepared,
        response => panic!("unexpected allocate response: {response:?}"),
    };
    let allocate_result_b =
        complete_generic_ceremony(&stack, &allocate_with_b, &prepared_b, &passkey_b, 2).await;
    assert_eq!(allocate_result_b.public_key_refs.len(), 1);

    // Recover access with a brand-new credential using only the recovery
    // factor: the recovery factor unwraps the same root.
    let recovery_operation = stack.next_operation();
    let recovery_request = custody_request(
        CeremonyKind::WalletRecovery,
        recovery_operation.clone(),
        Some(wallet_id.clone()),
        None,
        digest("81"),
        Token::new("recovery-factor-v1").unwrap(),
    );
    let recovery_prepared = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::RecoveryPrepare(recovery_request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::RecoveryPrepare(prepared) => prepared,
        response => panic!("unexpected recovery prepare response: {response:?}"),
    };
    let recovery_ceremony_id = stack
        .broker
        .ceremony()
        .public_status(&recovery_operation)
        .unwrap()
        .ceremony_id
        .to_string();
    let recovery_token = url_token(&recovery_prepared.ceremony_url);
    let recovery_session = get_session(
        stack.broker.as_ref(),
        &recovery_ceremony_id,
        &recovery_token,
    )
    .await;
    let recovery_attestation_challenge: CeremonyChallenge =
        serde_json::from_value(recovery_session["challenges"][0]["binding"].clone()).unwrap();
    let recovery_prf_challenge: CeremonyChallenge =
        serde_json::from_value(recovery_session["challenges"][1]["binding"].clone()).unwrap();
    let recovery_contribution: CustodySignerContribution =
        serde_json::from_value(recovery_session["signer_contribution"].clone()).unwrap();
    let recovery_attestation =
        recovery_credential.attestation(&recovery_attestation_challenge.canonical_bytes().unwrap());
    let recovery_prf_assertion =
        recovery_credential.assertion(&recovery_prf_challenge.canonical_bytes().unwrap(), 1);
    let recovery_aad = CustodyHpkeAad {
        ceremony_id: recovery_contribution.ceremony_id.clone(),
        ceremony_kind: bloom_signer_api::CeremonyKind::WalletRecovery,
        custody_operation_id: recovery_operation.clone(),
        signer_nonce: recovery_contribution.signer_nonce.clone(),
        signer_contribution_digest: recovery_contribution.digest().unwrap(),
        wallet_id: recovery_contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(recovery_attestation.credential_id.clone()),
        expected_input_class: Token::new("recovery-factor-v1").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let recovery_input = serde_jcs::to_vec(&serde_json::json!({
        "recovery_id": recovery["recovery_id"],
        "recovery_secret": recovery["recovery_secret"],
        "new_credential_prf": Base64UrlBytes::from_bytes(
            &recovery_credential.deterministic_prf()
        ),
    }))
    .unwrap();
    let recovery_encrypted = seal_hpke(
        &recovery_contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &recovery_aad,
        &recovery_input,
    )
    .unwrap();
    let recovery_status = post_complete(
        stack.broker.as_ref(),
        &recovery_ceremony_id,
        &recovery_token,
        serde_json::json!({
            "proof": {
                "kind": "recovery_credential_change",
                "new_credential_attestation": recovery_attestation,
                "new_credential_prf_assertion": recovery_prf_assertion
            },
            "encrypted_input": recovery_encrypted,
            "public_binding_digest": digest("81")
        }),
    )
    .await;
    assert_eq!(recovery_status, StatusCode::OK);

    // The recovery credential now allocates from the same root.
    let public_after_recovery = wallet_public(&stack, &wallet_id).await;
    let evm_two_operation = stack.next_operation();
    let evm_two_terms = allocation_terms(
        &public_after_recovery,
        DerivedAccountRequest {
            derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
            requested_role: Token::new("recovered-evm").unwrap(),
            account: Some(1),
        },
        evm_two_operation.clone(),
    );
    let evm_two_request = allocate_request(&wallet_id, evm_two_terms);
    let evm_two_prepared = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::AccountAllocatePrepare(evm_two_request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::AccountAllocatePrepare(prepared) => prepared,
        response => panic!("unexpected allocate response: {response:?}"),
    };
    let evm_two_result = complete_generic_ceremony(
        &stack,
        &evm_two_request,
        &evm_two_prepared,
        &recovery_credential,
        2,
    )
    .await;
    assert_eq!(evm_two_result.public_key_refs.len(), 1);

    // Every factor reached the same root: all children live under one seed
    // profile, and the passkey-A-registered EVM child is untouched.
    let accounts = wallet_accounts(&stack, &wallet_id).await;
    assert_eq!(accounts.seed_profile, WalletSeedProfile::Bip39MulticurveV1);
    assert_eq!(accounts.accounts.len(), 3);
    assert!(accounts.accounts.contains(&initial_evm));

    // Restart both services from disk: byte-identical projection.
    let before_restart = serde_jcs::to_string(&accounts).unwrap();
    drop(stack);
    let restarted = account_stack(directory.path(), "r2").await;
    let after_restart =
        serde_jcs::to_string(&wallet_accounts(&restarted, &wallet_id).await).unwrap();
    assert_eq!(before_restart, after_restart);

    // The recovery factor never leaked into Broker storage.
    scan_directory_for(
        directory.path(),
        &[
            recovery_plaintext.expose_to_backend().to_vec(),
            passkey_a.deterministic_prf().to_vec(),
            passkey_b.deterministic_prf().to_vec(),
            recovery_credential.deterministic_prf().to_vec(),
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_allocation_fails_closed_on_stale_and_foreign_terms() {
    let directory = tempfile::tempdir().unwrap();
    let mut stack = account_stack(directory.path(), "f1").await;
    let authenticator = VirtualAuthenticator::generate();
    let wallet_id = Token::new("fail-closed").unwrap();
    register_bip39_wallet(&mut stack, &wallet_id, &authenticator, None).await;
    let public = wallet_public(&stack, &wallet_id).await;

    // Stale policy baseline fails before Signer sees anything.
    let stale_operation = stack.next_operation();
    let mut stale = allocation_terms(&public, solana_derivation_request(), stale_operation);
    stale.policy_version = DecimalU64::new(public.policy_version.get() + 1);
    let error = MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::AccountAllocatePrepare(allocate_request(&wallet_id, stale)),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.code,
        bloom_broker_api::ProtocolErrorCode::OperationIdConflict
    );

    // Missing structured terms fail validation.
    let missing_operation = stack.next_operation();
    let mut missing = allocate_request(
        &wallet_id,
        allocation_terms(&public, solana_derivation_request(), missing_operation),
    );
    missing.account_terms = None;
    missing.exact_terms_digest = digest("91");
    assert!(
        MachineBrokerService::dispatch(
            stack.broker.as_ref(),
            MachineBrokerRequest::AccountAllocatePrepare(missing),
        )
        .await
        .is_err()
    );

    // Expired terms fail.
    let expired_operation = stack.next_operation();
    let mut expired = allocation_terms(&public, solana_derivation_request(), expired_operation);
    expired.expires_at_ms = DecimalU64::new(1);
    assert!(
        MachineBrokerService::dispatch(
            stack.broker.as_ref(),
            MachineBrokerRequest::AccountAllocatePrepare(allocate_request(&wallet_id, expired)),
        )
        .await
        .is_err()
    );

    // The imported-scalar profile is import-only: Signer rejects it on
    // registration, and the broker passes that rejection through untouched.
    let imported_operation = stack.next_operation();
    let mut imported_request = custody_request(
        CeremonyKind::WalletRegistration,
        imported_operation,
        Some(Token::new("imported-scalar-wallet").unwrap()),
        None,
        digest("a1"),
        Token::new("passkey-prf").unwrap(),
    );
    imported_request.wallet_seed_profile = Some(WalletSeedProfile::ImportedSecp256k1Scalar);
    let imported_error = MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::WalletRegistrationPrepare(imported_request),
    )
    .await
    .unwrap_err();
    assert_eq!(
        imported_error.code,
        bloom_broker_api::ProtocolErrorCode::CeremonyKindMismatch
    );

    // Retiring a foreign fingerprint fails closed.
    let retire_operation = stack.next_operation();
    let foreign_terms = AccountTerms {
        schema: Token::new("bloom.account_terms.v1").unwrap(),
        wallet_id: wallet_id.clone(),
        seed_profile: WalletSeedProfile::Bip39MulticurveV1,
        derivation: None,
        retire_key_fingerprint: Some(digest("ee")),
        path_template: DerivationProfile::Bip44SolanaSlip10Ed25519V1
            .path_template()
            .to_owned(),
        key_spec: KeySpec::Ed25519,
        allowed_crypto_suites: DerivationProfile::Bip44SolanaSlip10Ed25519V1
            .frozen_crypto_suites()
            .to_vec(),
        policy_version: public.policy_version.clone(),
        revocation_epoch: public.wallet_revocation_epoch.clone(),
        replay_id: retire_operation.clone(),
        expires_at_ms: DecimalU64::new(now_plus(600)),
        audit_purpose: Token::new("retire-derived-account").unwrap(),
    };
    let child = wallet_accounts(&stack, &wallet_id).await.accounts[0].clone();
    let mut foreign_request = custody_request(
        CeremonyKind::AccountRetire,
        retire_operation,
        Some(wallet_id.clone()),
        Some(child.key_ref.clone()),
        foreign_terms.request_digest().unwrap(),
        Token::new("generic-custody-v1").unwrap(),
    );
    foreign_request.account_terms = Some(foreign_terms);
    let foreign_error = MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::AccountRetirePrepare(foreign_request),
    )
    .await
    .unwrap_err();
    assert_eq!(
        foreign_error.code,
        bloom_broker_api::ProtocolErrorCode::OperationIdConflict
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_bip39_secret_scan_is_empty_across_sqlite_logs_and_responses() {
    struct SharedWriter {
        buffer: Arc<std::sync::Mutex<Vec<u8>>>,
    }
    impl std::io::Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.buffer.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl tracing_subscriber::fmt::MakeWriter<'_> for SharedWriter {
        type Writer = Self;
        fn make_writer(&self) -> Self::Writer {
            SharedWriter {
                buffer: self.buffer.clone(),
            }
        }
    }

    let log_buffer = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(SharedWriter {
            buffer: log_buffer.clone(),
        })
        .with_max_level(tracing::Level::INFO)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let directory = tempfile::tempdir().unwrap();
    let mut stack = account_stack(directory.path(), "s1").await;
    let authenticator = VirtualAuthenticator::generate();
    let wallet_id = Token::new("secret-scan").unwrap();
    let output_recipient = HpkeRecipient::generate();
    let (registration, registration_contribution) = register_bip39_wallet(
        &mut stack,
        &wallet_id,
        &authenticator,
        Some(&output_recipient),
    )
    .await;

    let public = wallet_public(&stack, &wallet_id).await;
    let allocate_operation = stack.next_operation();
    let terms = allocation_terms(&public, solana_derivation_request(), allocate_operation);
    let request = allocate_request(&wallet_id, terms);
    let prepared = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::AccountAllocatePrepare(request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::AccountAllocatePrepare(prepared) => prepared,
        response => panic!("unexpected allocate response: {response:?}"),
    };
    let result = complete_generic_ceremony(&stack, &request, &prepared, &authenticator, 2).await;
    let accounts = wallet_accounts(&stack, &wallet_id).await;

    // The recovery factor plaintext and every passkey PRF are the secret
    // corpus; none may appear in Broker sqlite stores, logs, or responses.
    let recovery_plaintext = output_recipient
        .open(
            &south_envelope(registration.encrypted_browser_result.as_ref().unwrap()),
            CUSTODY_OUTPUT_INFO,
            &CustodyOutputHpkeAad {
                ceremony_id: registration_contribution.ceremony_id.clone(),
                ceremony_kind: bloom_signer_api::CeremonyKind::WalletRegistration,
                custody_operation_id: registration.custody_operation_id.clone(),
                signer_contribution_digest: registration_contribution.digest().unwrap(),
                public_binding_digest: digest("61"),
            }
            .canonical_bytes()
            .unwrap(),
        )
        .unwrap();
    let secrets: Vec<Vec<u8>> = vec![
        recovery_plaintext.expose_to_backend().to_vec(),
        authenticator.deterministic_prf().to_vec(),
    ];
    let responses = format!(
        "{}{}{}",
        serde_json::to_string(&registration).unwrap(),
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&accounts).unwrap(),
    );
    for secret in &secrets {
        assert!(
            !responses
                .as_bytes()
                .windows(secret.len())
                .any(|window| window == secret.as_slice()),
            "secret material leaked into a Machine-facing response"
        );
    }
    drop(_guard);
    let logged = log_buffer.lock().unwrap().clone();
    for secret in &secrets {
        assert!(
            !logged
                .windows(secret.len())
                .any(|window| window == secret.as_slice()),
            "secret material leaked into Broker logs"
        );
    }
    scan_directory_for(directory.path(), &secrets).await;
}

async fn scan_directory_for(root: &Path, secrets: &[Vec<u8>]) {
    let mut queue = vec![root.to_path_buf()];
    while let Some(path) = queue.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).unwrap() {
                queue.push(entry.unwrap().path());
            }
            continue;
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "sock")
        {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        for secret in secrets {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_slice()),
                "secret material leaked into {}",
                path.display()
            );
        }
    }
}

/// An installer-signed `System` provenance record binding the `cli/sign`
/// subject, so the Broker authority will prepare and authorize a sign approval.
fn system_provenance() -> ProvenanceRecord {
    use ed25519_dalek::Signer as _;
    let mut record = ProvenanceRecord {
        subject: ProvenanceSubject::System {
            component_id: Token::new("cli").unwrap(),
            operation_class: Token::new("sign").unwrap(),
        },
        publisher: Token::new("installer").unwrap(),
        petal_lineage: None,
        operation_classes: vec![ProvenanceOperationClass {
            operation_class: Token::new("sign").unwrap(),
            fee_asset: None,
        }],
        installer_key_id: Token::new("installer-key").unwrap(),
        installer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    record.installer_signature = Base64UrlBytes::from_bytes(&[]);
    let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&record).unwrap());
    record.installer_signature =
        Base64UrlBytes::from_bytes(&SigningKey::from_bytes(&[5; 32]).sign(&message).to_bytes());
    record
}

/// Broker-side approval terms for an exact single-payload sign by a derived
/// child, bound to the wallet's live policy and a freshly installed provenance.
fn sign_terms(
    wallet: &WalletPublic,
    key_ref: KeyRef,
    payload: &[u8],
    provenance: &ProvenanceRecord,
) -> SealedApprovalTerms {
    let payload_hash = Digest32::from_bytes(Sha256::digest(payload).into());
    SealedApprovalTerms {
        subject: ApprovalSubject::System {
            component_id: Token::new("cli").unwrap(),
            operation_class: Token::new("sign").unwrap(),
        },
        wallet_id: wallet.wallet_id.clone(),
        key_ref,
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
        selector: ApprovalSelector::Exact {
            ordered_payload_digests: vec![payload_hash.clone()],
            ordered_hashes: vec![payload_hash],
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: wallet.wallet_revocation_epoch.clone(),
        policy_version: wallet.policy_version.clone(),
        policy_digest: wallet.policy_digest.clone(),
        provenance_digest: provenance.digest().unwrap(),
        request_nonce: RequestNonce::new("77".repeat(16)).unwrap(),
        issued_at_ms: DecimalU64::new(now_plus(0) - 1_000),
        not_before_ms: DecimalU64::new(now_plus(0) - 1_000),
        expires_at_ms: DecimalU64::new(now_plus(600)),
        renewal_of: None,
    }
}

/// Complete the browser SealedApproval ceremony that activates the backend and
/// installs the approval, then dispatch `signing.sign` and return the result.
async fn approve_and_sign(
    stack: &mut AccountStack,
    authenticator: &VirtualAuthenticator,
    terms: &SealedApprovalTerms,
    payload: &[u8],
    sign_count: u32,
) -> bloom_broker_api::SigningResult {
    let approval_operation = stack.next_operation();
    let approve_prepared = match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::SealedApprovalPrepare(bloom_broker_api::ApprovalPrepareRequest {
            operation_id: approval_operation.clone(),
            terms: terms.clone(),
            canonical_plan_facts_digest: terms.approval_digest().unwrap(),
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::SealedApprovalPrepare(prepared) => prepared,
        response => panic!("unexpected approval prepare response: {response:?}"),
    };
    let ceremony_id = stack
        .broker
        .ceremony()
        .public_status(&approval_operation)
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&approve_prepared.ceremony_url);
    let session = get_session(stack.broker.as_ref(), &ceremony_id, &token).await;
    let challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let contribution: SignerCeremonyContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let assertion = authenticator.assertion(&challenge.canonical_bytes().unwrap(), sign_count);
    let aad = LocalPrfHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        signer_nonce: contribution.signer_nonce.clone(),
        approval_id: terms.approval_id().unwrap(),
        approval_digest: contribution.approval_digest.clone(),
        review_manifest_digest: contribution.review_manifest_digest.clone(),
        key_ref: contribution.key_ref.clone(),
        allowed_crypto_suites: contribution.allowed_crypto_suites.clone(),
        credential_id: assertion.credential_id.clone(),
        activation_mode: contribution.activation_mode.clone(),
        wallet_revocation_epoch: contribution.wallet_revocation_epoch.clone(),
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_local_prf = seal_hpke(
        contribution
            .ephemeral_encryption_public_key
            .as_ref()
            .unwrap(),
        LOCAL_PRF_INFO,
        &aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let status = post_complete(
        stack.broker.as_ref(),
        &ceremony_id,
        &token,
        serde_json::json!({
            "proof": {
                "kind": "assertion",
                "assertion": assertion
            },
            "encrypted_input": encrypted_local_prf,
            "public_binding_digest": terms.approval_digest().unwrap()
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let sign_operation = stack.next_operation();
    let payload_hash = Digest32::from_bytes(Sha256::digest(payload).into());
    let identity = bloom_signer_api::SignOperationIdentity {
        operation_id: sign_operation.clone(),
        approval_id: terms.approval_id().unwrap(),
        key_ref: bloom_signer_api::KeyRef {
            backend: terms.key_ref.backend.clone(),
            backend_instance: terms.key_ref.backend_instance.clone(),
            locator: terms.key_ref.locator.clone(),
            key_spec: bloom_signer_api::KeySpec::Secp256k1,
            public_key_fingerprint: terms.key_ref.public_key_fingerprint.clone(),
            derivation: match &terms.key_ref.derivation {
                Some(bloom_broker_api::DerivationRef::Bip39Multicurve {
                    wallet_seed_ref,
                    profile,
                    path,
                }) => Some(bloom_signer_api::DerivationRef::Bip39Multicurve {
                    wallet_seed_ref: wallet_seed_ref.clone(),
                    profile: match profile {
                        DerivationProfile::Bip44EvmSecp256k1V1 => {
                            bloom_signer_api::DerivationProfile::Bip44EvmSecp256k1V1
                        }
                        DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
                            bloom_signer_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1
                        }
                    },
                    path: path.clone(),
                }),
                Some(bloom_broker_api::DerivationRef::Bip32Secp256k1 { root_key_id, path }) => {
                    Some(bloom_signer_api::DerivationRef::Bip32Secp256k1 {
                        root_key_id: root_key_id.clone(),
                        path: path.clone(),
                    })
                }
                None => None,
            },
        },
        crypto_suite: bloom_signer_api::CryptoSuite::Secp256k1Sha256Recoverable,
        ordered_payload_digests: vec![payload_hash.clone()],
        ordered_hashes: vec![payload_hash],
        petal_use_claim_digest: None,
        claim_assurance_digest: None,
        policy_version: terms.policy_version.clone(),
        policy_digest: terms.policy_digest.clone(),
    };
    let sign_request = MachineSignRequest {
        operation_id: sign_operation,
        operation_digest: identity.digest().unwrap(),
        approval_id: terms.approval_id().unwrap(),
        key_ref: terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        payloads: SigningPayloads::Single {
            payload: Base64UrlBytes::from_bytes(payload),
        },
        petal_use_claim: None,
        claim_assurance_evidence: None,
        provenance: ProvenanceSubject::System {
            component_id: Token::new("cli").unwrap(),
            operation_class: Token::new("sign").unwrap(),
        },
    };
    match MachineBrokerService::dispatch(
        stack.broker.as_ref(),
        MachineBrokerRequest::SigningSign(sign_request),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::SigningSign(result) => result,
        response => panic!("unexpected signing response: {response:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restored_wallet_signs_from_restored_derived_account_over_real_transport() {
    let directory = tempfile::tempdir().unwrap();
    let authenticator = VirtualAuthenticator::generate();
    let wallet_id = Token::new("restore-sign").unwrap();

    // Phase 1: register (canonical EVM child) and allocate a Solana sibling,
    // then export the Signer backup.
    let (evm_child, backup) = {
        let mut stack = account_stack(directory.path(), "s1").await;
        let (registration, _) =
            register_bip39_wallet(&mut stack, &wallet_id, &authenticator, None).await;
        let evm_child = registration.public_key_refs[0].clone();
        let allocate_operation = stack.next_operation();
        let public = wallet_public(&stack, &wallet_id).await;
        let terms = allocation_terms(
            &public,
            solana_derivation_request(),
            allocate_operation.clone(),
        );
        let request = allocate_request(&wallet_id, terms);
        let prepared = match MachineBrokerService::dispatch(
            stack.broker.as_ref(),
            MachineBrokerRequest::AccountAllocatePrepare(request.clone()),
        )
        .await
        .unwrap()
        {
            MachineBrokerResponse::AccountAllocatePrepare(prepared) => prepared,
            response => panic!("unexpected allocate response: {response:?}"),
        };
        let _solana_child =
            complete_generic_ceremony(&stack, &request, &prepared, &authenticator, 2).await;
        (
            evm_child,
            stack
                .signer_engine
                .export_wallet_backup(&wallet_id)
                .unwrap(),
        )
    };

    // Phase 2: wipe the Signer's durable store only (Broker authority, journal,
    // and ceremony state persist) and restore the exported backup into a fresh
    // Signer engine. This is the realistic "Signer lost and restored, Broker
    // restarted against it" restore.
    fs::remove_file(directory.path().join("signer.sqlite")).unwrap();
    let mut restored = account_stack_with_backup(directory.path(), "s2", Some(&backup)).await;
    let accounts = wallet_accounts(&restored, &wallet_id).await;
    assert_eq!(accounts.accounts.len(), 2);
    let evm_projection = accounts
        .accounts
        .iter()
        .find(|account| account.derivation_profile == DerivationProfile::Bip44EvmSecp256k1V1)
        .expect("restored EVM child is projected");
    assert_eq!(evm_projection.key_ref, evm_child);

    // The restored Signer ceremony service needs the passkey credential
    // re-registered (credentials are not part of the backup set), and the
    // Broker authority's provenance is installer-owned out-of-band state.
    // Both are re-established so the full sign ceremony can run end to end.
    restored
        .authority
        .install_provenance(&system_provenance())
        .unwrap();
    restored
        .signer_ceremony
        .register_existing_credential(wallet_id.clone(), authenticator.credential(0))
        .unwrap();

    let public = wallet_public(&restored, &wallet_id).await;
    let payload = b"restored-derived-account-signature";
    let terms = sign_terms(&public, evm_child.clone(), payload, &system_provenance());
    let result = approve_and_sign(&mut restored, &authenticator, &terms, payload, 2).await;
    assert_eq!(result.signatures.len(), 1);
    assert_eq!(
        result.signatures[0].crypto_suite,
        CryptoSuite::Secp256k1Sha256Recoverable
    );

    // The signature verifies under the restored descriptor's public key.
    let descriptor = restored
        .signer_engine
        .derived_account_descriptor(&bloom_signer_api::KeyRef {
            backend: evm_child.backend.clone(),
            backend_instance: evm_child.backend_instance.clone(),
            locator: evm_child.locator.clone(),
            key_spec: bloom_signer_api::KeySpec::Secp256k1,
            public_key_fingerprint: evm_child.public_key_fingerprint.clone(),
            derivation: match &evm_child.derivation {
                Some(bloom_broker_api::DerivationRef::Bip39Multicurve {
                    wallet_seed_ref,
                    profile,
                    path,
                }) => Some(bloom_signer_api::DerivationRef::Bip39Multicurve {
                    wallet_seed_ref: wallet_seed_ref.clone(),
                    profile: match profile {
                        DerivationProfile::Bip44EvmSecp256k1V1 => {
                            bloom_signer_api::DerivationProfile::Bip44EvmSecp256k1V1
                        }
                        DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
                            bloom_signer_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1
                        }
                    },
                    path: path.clone(),
                }),
                Some(bloom_broker_api::DerivationRef::Bip32Secp256k1 { root_key_id, path }) => {
                    Some(bloom_signer_api::DerivationRef::Bip32Secp256k1 {
                        root_key_id: root_key_id.clone(),
                        path: path.clone(),
                    })
                }
                None => None,
            },
        })
        .unwrap()
        .unwrap();
    let bytes = result.signatures[0].bytes.decode();
    let digest: [u8; 32] = Sha256::digest(payload).into();
    let sig = k256::ecdsa::Signature::from_slice(&bytes[..64]).unwrap();
    let recovery = k256::ecdsa::RecoveryId::from_byte(bytes[64]).unwrap();
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();
    let spki = k256::PublicKey::from_sec1_bytes(recovered.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
    assert_eq!(descriptor.canonical_public_key.decode(), spki.as_bytes());
}
