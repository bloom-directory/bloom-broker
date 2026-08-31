//! Owner review and admission for runtime package registrations.
use super::*;
use crate::{
    authority::BrokerAuthority,
    service::authority_error,
    translation::{custody::result_to_machine, petal_registration::terms_to_signer},
};
use bloom_broker_api::{
    PetalRegistration, PetalRegistrationCommitRequest, PetalRegistrationPrepareRequest,
    PetalRegistrationPrepareResponse, PetalRegistrationTerms, canonical_petal_registration_request,
};

impl CeremonyBroker {
    pub(crate) fn prepare_petal_registration(
        &self,
        authority: &BrokerAuthority,
        request: &PetalRegistrationPrepareRequest,
        now_ms: u64,
    ) -> Result<PetalRegistrationPrepareResponse, ProtocolError> {
        let request = canonical_petal_registration_request(request)?;
        self.expire_sessions(now_ms)?;
        // Lock order: admission -> short authority barrier/database operations.
        // No authority/database mutex is held across a Signer call or owner interaction.
        let _admission = self.inner.creation_admission.lock();
        let mut existing = authority
            .existing_petal_registration_candidate(&request)
            .map_err(authority_error)?;
        if let Some(terms) = &existing {
            let (mut proposal, _) = authority
                .petal_registration_proposal(&terms.operation_id)
                .map_err(authority_error)?;
            proposal.operation_id = request.operation_id.clone();
            let same_proposal = proposal == request;
            if let Some(registration) = authority
                .petal_registration(&terms.package_hash)
                .map_err(authority_error)?
            {
                if !same_proposal {
                    return Err(operation_conflict());
                }
                return Ok(PetalRegistrationPrepareResponse::Registered { registration });
            }
            match self
                .inner
                .signer
                .status(&terms.operation_id)
                .map_err(signer_error_to_machine)?
            {
                SignerCeremonyStatus::CompletedCustody(receipt) => {
                    let registration = authority
                        .commit_petal_registration(&PetalRegistrationCommitRequest {
                            operation_id: terms.operation_id.clone(),
                            ceremony_receipt: result_to_machine(*receipt),
                        })
                        .map_err(authority_error)?;
                    // Recover the original approved consent even when the caller
                    // proposes different terms. Approval can never be replaced.
                    if !same_proposal {
                        return Err(operation_conflict());
                    }
                    return Ok(PetalRegistrationPrepareResponse::Registered { registration });
                }
                SignerCeremonyStatus::CompletedApproval(_) => return Err(kind_mismatch()),
                // A reserved attempt may precede any Signer effect (including a
                // lost transport request). Keep its operation and quota identity.
                SignerCeremonyStatus::Missing if self.status(&terms.operation_id).is_none() => {}
                SignerCeremonyStatus::Terminal(_) | SignerCeremonyStatus::Missing => {
                    authority
                        .abandon_petal_registration(&terms.operation_id)
                        .map_err(authority_error)?;
                    existing = None;
                }
                SignerCeremonyStatus::Pending => {}
            }
            if existing.is_some() && !same_proposal {
                return Err(operation_conflict());
            }
        }
        if existing.is_none() {
            self.enforce_creation_bounds(Some(&request.owner_wallet_id), false, now_ms)?;
            // The shared anonymous admission policy also bounds failed reservations:
            // wallet IDs in a prepare request have not yet authenticated the caller.
            authority
                .consume_mutation_quota(
                    "petal-registration-preparations",
                    now_ms,
                    self.inner.limits.creation_window_ms,
                    self.inner.limits.maximum_anonymous_registrations as u64,
                )
                .map_err(authority_error)?;
        }
        let terms = match existing {
            Some(terms) => terms,
            None => authority
                .prepare_petal_registration(&request)
                .map_err(authority_error)?,
        };
        let (proposal, stored_terms) = authority
            .petal_registration_proposal(&terms.operation_id)
            .map_err(authority_error)?;
        if stored_terms != terms {
            return Err(operation_conflict());
        }
        let review = registration_review(&proposal, &terms)?;
        let typed = bloom_signer_api::PetalRegistrationCeremonyPrepareRequest {
            custody: CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::PetalRegistration,
                custody_operation_id: terms.operation_id.clone(),
                wallet_id: Some(terms.owner_wallet_id.clone()),
                key_ref: None,
                exact_terms_digest: terms.digest()?,
                expected_input_class: Token::new("petal_registration")?,
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
            },
            terms: terms_to_signer(terms.clone()),
        };
        typed.validate_binding().map_err(signer_error_to_machine)?;
        let request_digest = digest(&(typed.clone(), review.clone()))?;
        if let Some(ceremony) = self.stable_custody_response(&terms.operation_id, &request_digest) {
            return Ok(PetalRegistrationPrepareResponse::AwaitingApproval {
                terms,
                ceremony: ceremony?,
            });
        }
        self.enforce_creation_bounds(Some(&terms.owner_wallet_id), false, now_ms)?;
        let prepared = match self.inner.signer.prepare_petal_registration(typed, now_ms) {
            Ok(prepared) => prepared,
            Err(error) => {
                let contract = error.code.contract();
                if contract.durable_effect == bloom_signer_api::DurableEffect::None
                    && contract.retry == bloom_signer_api::RetryClass::Never
                {
                    authority
                        .abandon_petal_registration(&terms.operation_id)
                        .map_err(authority_error)?;
                }
                // Unknown outcomes retain their exact reserved operation and lineage.
                return Err(signer_error_to_machine(error));
            }
        };
        let contribution = &prepared.contribution;
        if contribution.ceremony_kind != CeremonyKind::PetalRegistration
            || contribution.custody_operation_id != terms.operation_id
            || contribution.wallet_id.as_ref() != Some(&terms.owner_wallet_id)
            || contribution.review_manifest_digest != terms.digest()?
            || contribution.key_ref.is_some()
            || contribution.browser_output_recipient_key.is_some()
            || contribution.petal_key_scope.is_some()
            || contribution.expected_input_class.as_str() != "petal_registration"
            || !contribution.required_user_verification
            || prepared.challenges.len() != 1
            || prepared.challenges.iter().any(|challenge| {
                challenge.operation_id != terms.operation_id
                    || challenge.ceremony_kind != CeremonyKind::PetalRegistration
                    || challenge.exact_terms_digest != contribution.review_manifest_digest
                    || challenge.review_manifest_digest != contribution.review_manifest_digest
            })
        {
            return Err(kind_mismatch());
        }
        let ceremony_id = contribution.ceremony_id.clone();
        let expires_at_ms = contribution.expires_at_ms.get();
        let contribution_digest = contribution.digest().map_err(signer_error_to_machine)?;
        let session = self.new_session(NewBrowserSession {
            operation_id: terms.operation_id.clone(),
            request_digest,
            wallet_id: Some(terms.owner_wallet_id.clone()),
            anonymous_registration: false,
            ceremony_kind: CeremonyKind::PetalRegistration,
            ceremony_id: ceremony_id.clone(),
            review_manifest: Some(review),
            challenges: prepared.challenges,
            signer_contribution: serde_json::to_value(prepared.contribution).map_err(malformed)?,
            webauthn_options: prepared.webauthn_options,
            verification_credentials: prepared.verification_credentials,
            policy_update: None,
            expires_at_ms,
            created_at_ms: now_ms,
        })?;
        let ceremony = CustodyPrepareResponse {
            ceremony_kind: BrokerCeremonyKind::PetalRegistration,
            custody_operation_id: terms.operation_id.clone(),
            state: CustodyPrepareState::AwaitingUser,
            ceremony_url: session_url(&token_for(&session)),
            ceremony_expires_at_ms: DecimalU64::new(expires_at_ms),
            signer_contribution_digest: contribution_digest,
        };
        self.insert_session(ceremony_id, session)?;
        Ok(PetalRegistrationPrepareResponse::AwaitingApproval { terms, ceremony })
    }

    pub(crate) fn commit_petal_registration(
        &self,
        authority: &BrokerAuthority,
        request: &PetalRegistrationCommitRequest,
    ) -> Result<PetalRegistration, ProtocolError> {
        let (_, terms) = authority
            .petal_registration_proposal(&request.operation_id)
            .map_err(authority_error)?;
        if let Some(record) = authority
            .petal_registration(&terms.package_hash)
            .map_err(authority_error)?
        {
            if record.ceremony_receipt != request.ceremony_receipt {
                return Err(operation_conflict());
            }
            return Ok(record);
        }
        match self
            .inner
            .signer
            .status(&request.operation_id)
            .map_err(signer_error_to_machine)?
        {
            SignerCeremonyStatus::CompletedCustody(receipt)
                if result_to_machine(*receipt.clone()) == request.ceremony_receipt =>
            {
                authority
                    .commit_petal_registration(request)
                    .map_err(authority_error)
            }
            _ => Err(protocol(
                ProtocolErrorCode::CeremonyKindMismatch,
                "registration requires its exact completed Signer owner ceremony",
            )),
        }
    }
}

fn registration_review(
    request: &PetalRegistrationPrepareRequest,
    terms: &PetalRegistrationTerms,
) -> Result<serde_json::Value, ProtocolError> {
    // Every variable review field derives from the exact manifest/permission bytes
    // committed by terms.digest(), which is the signed WebAuthn review binding.
    let bounds = bloom_petal_package::parse_manifest_bounds(&request.evidence.manifest_utf8)
        .map_err(malformed)?;
    let manifest = bloom_petal_package::manifest::parse_manifest(&request.evidence.manifest_utf8)
        .map_err(malformed)?;
    let delegated = request
        .requested_routes
        .iter()
        .filter(|route| {
            route
                .capabilities
                .iter()
                .any(|cap| cap == "bloom:tx.outbox")
        })
        .map(|route| {
            (
                route.route_id.clone(),
                serde_json::json!([
                    "transaction.confirm",
                    "transaction.replace",
                    "transaction.cancel"
                ]),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    Ok(serde_json::json!({
        "schema":"bloom.petal-registration-review/1", "title":"Requested permissions",
        "terms":terms, "review_digest":terms.digest()?, "manifest_bounds":bounds,
        "requested_permissions":request.requested_routes, "source":manifest._source, "source_verified":false,
        "source_disclosure":"Source information is unverified. Broker checks static manifest bounds, not Petal behavior or transaction meaning.",
        "owner_wallet_role":"Authenticate this registration only",
        "disclaimer":"This does not grant wallet access or approve transactions.",
        "delegated_transaction_requests":delegated,
    }))
}
