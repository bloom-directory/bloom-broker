//! Card ceremonies share Broker's browser sessions; release delivery is private.
use super::*;
use bloom_signer_api::{
    CardEffect, CardOperationStatus, CardPrepareRequest, CardPublic, CheckoutFacts,
    CustodyOutputHpkeAad,
};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Default)]
pub(super) struct CardChannels {
    channels: Mutex<HashMap<OperationId, Channel>>,
}
struct Channel {
    challenge_url: String,
    result: Option<CustodyResult>,
    expires_at_ms: u64,
    output_aad: CustodyOutputHpkeAad,
}
impl CardChannels {
    pub(super) fn forget(&self, operation_id: &OperationId) {
        self.channels.lock().remove(operation_id);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckoutIntakeRequest {
    Prepare {
        operation_id: OperationId,
        card_id: Token,
        facts: CheckoutFacts,
        recipient_key: Base64UrlBytes,
        agent_description: String,
        challenge_url: String,
    },
    Manual {
        operation_id: OperationId,
        card_id: Token,
        agent_description: String,
        challenge_url: String,
    },
    Result {
        operation_id: OperationId,
    },
    Cancel {
        operation_id: OperationId,
    },
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckoutIntakeResponse {
    Prepared(CustodyPrepareResponse),
    Result {
        status: CardOperationStatus,
        receipt: Option<CustodyResult>,
        output_aad: Option<CustodyOutputHpkeAad>,
    },
    Error {
        message: String,
    },
}

pub(super) fn is_card(kind: CeremonyKind) -> bool {
    matches!(
        kind,
        CeremonyKind::CardAdd | CeremonyKind::CardDelete | CeremonyKind::CardCheckout
    )
}

impl CeremonyBroker {
    pub fn card_list(&self) -> Result<Vec<CardPublic>, ProtocolError> {
        self.inner
            .signer
            .card_list()
            .map_err(signer_error_to_machine)
    }
    pub fn card_status(
        &self,
        operation_id: &OperationId,
    ) -> Result<CardOperationStatus, ProtocolError> {
        self.inner
            .signer
            .card_status(operation_id)
            .map_err(signer_error_to_machine)
    }
    pub fn card_cancel(
        &self,
        operation_id: &OperationId,
        now_ms: u64,
    ) -> Result<CardOperationStatus, ProtocolError> {
        self.cancel(operation_id, now_ms)?;
        self.inner.cards.channels.lock().remove(operation_id);
        self.card_status(operation_id)
    }

    pub fn prepare_card(
        &self,
        operation_id: OperationId,
        effect: CardEffect,
        now_ms: u64,
    ) -> Result<CustodyPrepareResponse, ProtocolError> {
        self.expire_sessions(now_ms)?;
        let surface = self
            .select_surface(CeremonySurfaceSelection::Local)?
            .reference();
        let request = CardPrepareRequest {
            operation_id: operation_id.clone(),
            surface,
            effect,
        };
        let request_digest = request.digest().map_err(signer_error_to_machine)?;
        let _guard = self.inner.creation_admission.lock();
        if let Some(response) = self.stable_custody_response(&operation_id, &request_digest) {
            return response;
        }
        self.enforce_creation_bounds(None, true, now_ms)?;
        let card = self
            .card_list()?
            .into_iter()
            .find(|c| c.card_id == *request.effect.card_id());
        let prepared = self
            .inner
            .signer
            .prepare_card(request.clone(), now_ms)
            .map_err(signer_error_to_machine)?;
        if prepared.contribution.review_manifest_digest != request_digest
            || prepared.contribution.custody_operation_id != operation_id
            || prepared.contribution.ceremony_kind != request.effect.ceremony_kind()
            || prepared.contribution.surface != request.surface
            || prepared.contribution.wallet_id.is_some()
            || prepared.contribution.expires_at_ms.get() > now_ms.saturating_add(120_000)
        {
            return Err(operation_conflict());
        }
        let kind = request.effect.ceremony_kind();
        let review = serde_json::json!({"card_effect":request.effect, "card":card,
            "heading":custody_review_text(kind).0, "body":custody_review_text(kind).1});
        let origin = self.origin_for_surface(&prepared.contribution.surface)?;
        let contribution_digest = prepared
            .contribution
            .digest()
            .map_err(signer_error_to_machine)?;
        let expires_at_ms = prepared.contribution.expires_at_ms.get();
        let ceremony_id = prepared.contribution.ceremony_id.clone();
        let session = self.new_session(NewBrowserSession {
            operation_id: operation_id.clone(),
            request_digest,
            wallet_id: None,
            anonymous_registration: true,
            ceremony_kind: kind,
            ceremony_id: ceremony_id.clone(),
            review_manifest: Some(review),
            challenges: prepared.challenges,
            signer_contribution: serde_json::to_value(prepared.contribution).map_err(malformed)?,
            webauthn_options: prepared.webauthn_options,
            verification_credentials: prepared.verification_credentials,
            policy_update: None,
            expires_at_ms,
            created_at_ms: now_ms,
            origin,
        })?;
        let url = session_url(&session);
        self.insert_session(ceremony_id, session)?;
        Ok(CustodyPrepareResponse {
            ceremony_kind: kind_to_machine(kind),
            custody_operation_id: operation_id,
            state: CustodyPrepareState::AwaitingUser,
            ceremony_url: url,
            ceremony_expires_at_ms: DecimalU64::new(expires_at_ms),
            signer_contribution_digest: contribution_digest,
        })
    }

    fn checkout_intake(
        &self,
        request: CheckoutIntakeRequest,
    ) -> Result<CheckoutIntakeResponse, ProtocolError> {
        let now_ms = unix_time_ms();
        match request {
            CheckoutIntakeRequest::Prepare {
                operation_id,
                card_id,
                facts,
                recipient_key,
                agent_description,
                challenge_url,
            } => {
                // The principal owns this private capability. Never put it in a public projection.
                let effect = CardEffect::Checkout {
                    card_id,
                    facts,
                    recipient_key,
                    agent_description,
                };
                self.prepare_checkout_channel(operation_id, effect, challenge_url, now_ms)
            }
            CheckoutIntakeRequest::Manual {
                operation_id,
                card_id,
                agent_description,
                challenge_url,
            } => self.prepare_checkout_channel(
                operation_id,
                CardEffect::ManualCheckout {
                    card_id,
                    agent_description,
                },
                challenge_url,
                now_ms,
            ),
            CheckoutIntakeRequest::Result { operation_id } => {
                self.expire_sessions(now_ms)?;
                let status = self.card_status(&operation_id)?;
                let mut channels = self.inner.cards.channels.lock();
                let channel = channels.get_mut(&operation_id);
                let output_aad = channel.as_ref().map(|c| c.output_aad.clone());
                let receipt = channel.and_then(|c| c.result.take());
                Ok(CheckoutIntakeResponse::Result {
                    status,
                    receipt,
                    output_aad,
                })
            }
            CheckoutIntakeRequest::Cancel { operation_id } => {
                let status = self.card_cancel(&operation_id, now_ms)?;
                Ok(CheckoutIntakeResponse::Result {
                    status,
                    receipt: None,
                    output_aad: None,
                })
            }
        }
    }

    fn prepare_checkout_channel(
        &self,
        operation_id: OperationId,
        effect: CardEffect,
        challenge_url: String,
        now_ms: u64,
    ) -> Result<CheckoutIntakeResponse, ProtocolError> {
        let url = url::Url::parse(&challenge_url).map_err(|_| kind_mismatch())?;
        if challenge_url.len() > 256
            || url.scheme() != "http"
            || url.host_str() != Some("localhost")
            || url.port().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(kind_mismatch());
        }
        if self
            .inner
            .cards
            .channels
            .lock()
            .get(&operation_id)
            .is_some_and(|c| c.challenge_url != challenge_url)
        {
            return Err(operation_conflict());
        }
        let prepared = self.prepare_card(operation_id.clone(), effect, now_ms)?;
        let sessions = self.inner.sessions.lock();
        let session = sessions
            .values()
            .find(|s| s.operation_id == operation_id)
            .ok_or_else(operation_conflict)?;
        let contribution: CustodySignerContribution =
            serde_json::from_value(session.projection.signer_contribution.clone())
                .map_err(malformed)?;
        let output_aad = CustodyOutputHpkeAad {
            surface: contribution.surface.clone(),
            ceremony_id: contribution.ceremony_id.clone(),
            ceremony_kind: contribution.ceremony_kind,
            custody_operation_id: operation_id.clone(),
            signer_contribution_digest: contribution.digest().map_err(signer_error_to_machine)?,
            public_binding_digest: contribution.review_manifest_digest,
        };
        drop(sessions);
        let mut channels = self.inner.cards.channels.lock();
        channels.retain(|_, c| c.expires_at_ms > now_ms);
        channels.entry(operation_id).or_insert(Channel {
            challenge_url,
            result: None,
            expires_at_ms: prepared.ceremony_expires_at_ms.get(),
            output_aad,
        });
        Ok(CheckoutIntakeResponse::Prepared(prepared))
    }
}

pub(super) fn complete_card_session(
    broker: &CeremonyBroker,
    id: &str,
    mut session: BrowserSession,
    body: BrowserComplete,
) -> Response {
    let now_ms = unix_time_ms();
    let result = broker
        .inner
        .signer
        .complete_card(
            CustodyCompleteRequest {
                ceremony_kind: session.ceremony_kind,
                custody_operation_id: session.operation_id.clone(),
                ceremony_id: session.projection.ceremony_id.clone(),
                proof: body.proof,
                encrypted_input: body.encrypted_input,
                public_binding_digest: body.public_binding_digest,
            },
            now_ms,
        )
        .map_err(signer_error_to_machine);
    let response = match result {
        Ok(receipt) => {
            if receipt.ceremony_kind != session.ceremony_kind
                || receipt.custody_operation_id != session.operation_id
            {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            session.state = CeremonyState::Succeeded;
            // Never persist release ciphertext or expose a challenge URL via result/status.
            let challenge_url = if session.ceremony_kind == CeremonyKind::CardCheckout {
                let mut channels = broker.inner.cards.channels.lock();
                if let Some(channel) = channels.get_mut(&session.operation_id) {
                    channel.result = Some(receipt);
                    Some(channel.challenge_url.clone())
                } else {
                    session.state = CeremonyState::Failed;
                    None
                }
            } else {
                None
            };
            Json(serde_json::json!({"state":session.state, "challenge_url":challenge_url}))
                .into_response()
        }
        Err(_) => {
            session.state = CeremonyState::Failed;
            (StatusCode::CONFLICT, Json(serde_json::json!({"message":"Card approval failed or its disclosure outcome is unknown. Do not retry this request."}))).into_response()
        }
    };
    session.terminal_result = None;
    latch_terminal(&mut session, now_ms);
    if broker.persist_session(&session).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    broker.inner.sessions.lock().insert(id.to_owned(), session);
    response
}

/// Facts and encrypted output cross only this UID-authenticated local edge.
pub async fn serve_checkout_intake(
    broker: CeremonyBroker,
    path: &Path,
    checkout_uid: u32,
) -> std::io::Result<()> {
    let listener = bind_checkout_intake(path)?;
    serve_checkout_listener(broker, listener, checkout_uid).await
}

/// Bind before advertising service readiness. Never replace an existing path.
pub fn bind_checkout_intake(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

pub async fn serve_checkout_listener(
    broker: CeremonyBroker,
    listener: tokio::net::UnixListener,
    checkout_uid: u32,
) -> std::io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let (stream, _) = listener.accept().await?;
        if stream.peer_cred()?.uid() != checkout_uid {
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let broker = broker.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let (input, mut output) = stream.into_split();
            let mut line = String::new();
            let mut input = BufReader::new(input.take(16_385));
            if !matches!(
                tokio::time::timeout(Duration::from_secs(10), input.read_line(&mut line)).await,
                Ok(Ok(_))
            ) || line.len() > 16_384
            {
                return;
            }
            let response = match serde_json::from_str(&line) {
                Ok(request) => {
                    broker
                        .checkout_intake(request)
                        .unwrap_or(CheckoutIntakeResponse::Error {
                            message: "Checkout request rejected".into(),
                        })
                }
                Err(_) => CheckoutIntakeResponse::Error {
                    message: "Invalid checkout request".into(),
                },
            };
            if let Ok(mut bytes) = serde_json::to_vec(&response) {
                bytes.push(b'\n');
                let _ = output.write_all(&bytes).await;
            }
        });
    }
}
