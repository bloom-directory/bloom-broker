//! Runtime owner registrations, separate from installer catalog projections.
use super::*;
use bloom_broker_api::{
    PETAL_REGISTRATION_SCHEMA, PetalRegistration, PetalRegistrationCommitRequest,
    PetalRegistrationPrepareRequest, PetalRegistrationReceipt, PetalRegistrationTerms,
    canonical_petal_registration_request, petal_registration_manifest_digest,
    petal_registration_permissions_digest,
};
use rand::{RngCore, rngs::OsRng};

pub(super) fn initialize(connection: &Connection) -> Result<(), AuthorityError> {
    connection.execute_batch("
        CREATE TABLE IF NOT EXISTS petal_registration_identities (
            enrollment_digest TEXT NOT NULL, package_hash TEXT NOT NULL, lineage_id TEXT NOT NULL,
            PRIMARY KEY(enrollment_digest, package_hash)
        );
        CREATE TABLE IF NOT EXISTS petal_registration_attempts (
            operation_id TEXT PRIMARY KEY, enrollment_digest TEXT NOT NULL, package_hash TEXT NOT NULL,
            request_jcs TEXT NOT NULL, terms_jcs TEXT NOT NULL, state TEXT NOT NULL,
            receipt_jcs TEXT, record_jcs TEXT,
            FOREIGN KEY(enrollment_digest, package_hash) REFERENCES petal_registration_identities
        );
        CREATE UNIQUE INDEX IF NOT EXISTS petal_registration_active_identity
            ON petal_registration_attempts(enrollment_digest, package_hash)
            WHERE state IN ('prepared', 'completed', 'committed');
    ")?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct Attempt {
    request: PetalRegistrationPrepareRequest,
    terms: PetalRegistrationTerms,
    state: String,
    receipt: Option<PetalRegistrationReceipt>,
    record: Option<PetalRegistration>,
}

impl BrokerAuthority {
    pub(crate) fn validate_owner_attestation_prepare(
        &self,
        terms: &bloom_signer_api::OwnerAttestationTerms,
        prepared: &bloom_signer_api::PreparedOwnerAttestation,
    ) -> Result<(), AuthorityError> {
        if terms.authority_edge_digest != self.authority_edge_digest
            || prepared.contribution.operation_id != terms.operation_id
            || prepared.contribution.terms_digest != terms.digest().map_err(invalid)?
            || prepared.contribution.signer_key_id != self.ceremony_key_id
        {
            return Err(invalid_missing());
        }
        let signature = Signature::from_slice(&prepared.contribution.signer_signature.decode())
            .map_err(invalid)?;
        self.ceremony_key
            .verify_strict(
                &prepared.contribution.signature_message().map_err(invalid)?,
                &signature,
            )
            .map_err(invalid)
    }

    pub fn prepare_petal_registration(
        &self,
        request: &PetalRegistrationPrepareRequest,
    ) -> Result<PetalRegistrationTerms, AuthorityError> {
        let request = canonical_petal_registration_request(request).map_err(invalid)?;
        let _barrier = self.lock_authorization_barrier()?;
        let mut connection = self.lock_for_mutation()?;
        if let Some(attempt) = self.find_registration_attempt(&connection, &request)? {
            return Ok(attempt.terms);
        }
        let transaction = connection.transaction()?;
        let lineage: Option<String> = transaction.query_row(
            "SELECT lineage_id FROM petal_registration_identities WHERE enrollment_digest=?1 AND package_hash=?2",
            params![self.enrollment_digest.as_str(), request.evidence.package_hash], |row| row.get(0),
        ).optional()?;
        let lineage_id = lineage.unwrap_or_else(random_lineage);
        transaction.execute(
            "INSERT OR IGNORE INTO petal_registration_identities(enrollment_digest,package_hash,lineage_id) VALUES (?1,?2,?3)",
            params![self.enrollment_digest.as_str(), request.evidence.package_hash, lineage_id],
        )?;
        let terms = PetalRegistrationTerms {
            schema: Token::new(PETAL_REGISTRATION_SCHEMA).map_err(invalid)?,
            operation_id: request.operation_id.clone(),
            enrollment_digest: self.enrollment_digest.clone(),
            owner_wallet_id: request.owner_wallet_id.clone(),
            package_hash: Digest32::new(request.evidence.package_hash.clone()).map_err(invalid)?,
            manifest_digest: petal_registration_manifest_digest(&request.evidence.manifest_utf8)
                .map_err(invalid)?,
            permissions_digest: petal_registration_permissions_digest(&request.requested_routes)
                .map_err(invalid)?,
            lineage_id,
        };
        terms.validate_shape().map_err(invalid)?;
        transaction.execute(
            "INSERT INTO petal_registration_attempts(operation_id,enrollment_digest,package_hash,request_jcs,terms_jcs,state) VALUES (?1,?2,?3,?4,?5,'prepared')",
            params![terms.operation_id.as_str(), terms.enrollment_digest.as_str(), terms.package_hash.as_str(), canonical(&request)?, canonical(&terms)?],
        )?;
        self.journal.append_external_audit(
            &transaction,
            "petal.registration_prepared",
            &serde_json::json!({"request": request, "terms": terms}),
        )?;
        transaction.commit()?;
        drop(connection);
        self.journal.checkpoint_committed_head()?;
        Ok(terms)
    }

    /// Find a verified candidate before reconciling its Signer lifecycle.
    /// A package match may have different terms; callers must compare after recovery.
    pub(crate) fn existing_petal_registration_candidate(
        &self,
        request: &PetalRegistrationPrepareRequest,
    ) -> Result<Option<PetalRegistrationTerms>, AuthorityError> {
        let request = canonical_petal_registration_request(request).map_err(invalid)?;
        let connection = self.lock()?;
        Ok(self
            .find_registration_candidate(&connection, &request)?
            .map(|attempt| attempt.terms))
    }

    fn find_registration_attempt(
        &self,
        connection: &Connection,
        request: &PetalRegistrationPrepareRequest,
    ) -> Result<Option<Attempt>, AuthorityError> {
        let existing = self.find_registration_candidate(connection, request)?;
        if let Some(attempt) = &existing {
            let mut same = request.clone();
            same.operation_id = attempt.request.operation_id.clone();
            if same != attempt.request {
                return Err(conflict());
            }
        }
        Ok(existing)
    }

    fn find_registration_candidate(
        &self,
        connection: &Connection,
        request: &PetalRegistrationPrepareRequest,
    ) -> Result<Option<Attempt>, AuthorityError> {
        let by_operation = read_attempt(
            connection,
            "operation_id=?1",
            [request.operation_id.as_str()],
        )?;
        if let Some(attempt) = by_operation {
            self.validate_attempt(&attempt)?;
            if attempt.request != *request
                || !matches!(
                    attempt.state.as_str(),
                    "prepared" | "completed" | "committed"
                )
            {
                return Err(conflict());
            }
            return Ok(Some(attempt));
        }
        let existing = read_attempt(
            connection,
            "enrollment_digest=?1 AND package_hash=?2 AND state IN ('prepared','completed','committed')",
            [
                self.enrollment_digest.as_str(),
                request.evidence.package_hash.as_str(),
            ],
        )?;
        if let Some(attempt) = &existing {
            self.validate_attempt(attempt)?;
        }
        Ok(existing)
    }

    /// A terminal Signer/browser status permits a new operation, never new lineage.
    pub(crate) fn abandon_petal_registration(
        &self,
        operation: &OperationId,
    ) -> Result<(), AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        let mut connection = self.lock_for_mutation()?;
        let transaction = connection.transaction()?;
        let changed = transaction.execute("UPDATE petal_registration_attempts SET state='abandoned' WHERE operation_id=?1 AND state='prepared'", [operation.as_str()])?;
        if changed != 0 {
            self.journal.append_external_audit(
                &transaction,
                "petal.registration_abandoned",
                &serde_json::json!({"operation_id": operation}),
            )?;
        }
        transaction.commit()?;
        drop(connection);
        self.journal.checkpoint_committed_head()?;
        Ok(())
    }

    /// Keep the validated receipt durable before returning browser completion.
    pub(crate) fn complete_petal_registration(
        &self,
        receipt: &PetalRegistrationReceipt,
    ) -> Result<(), AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        let mut connection = self.lock_for_mutation()?;
        let attempt = read_attempt(
            &connection,
            "operation_id=?1",
            [receipt.operation_id.as_str()],
        )?
        .ok_or_else(invalid_missing)?;
        self.validate_attempt(&attempt)?;
        self.validate_registration_receipt(&attempt.terms, receipt)?;
        if let Some(stored) = &attempt.receipt {
            return if stored == receipt {
                Ok(())
            } else {
                Err(conflict())
            };
        }
        if attempt.state != "prepared" {
            return Err(conflict());
        }
        let transaction = connection.transaction()?;
        transaction.execute("UPDATE petal_registration_attempts SET state='completed',receipt_jcs=?2 WHERE operation_id=?1", params![receipt.operation_id.as_str(),canonical(receipt)?])?;
        self.journal.append_external_audit(
            &transaction,
            "petal.registration_completed",
            &serde_json::json!({"terms": attempt.terms,"receipt":receipt}),
        )?;
        transaction.commit()?;
        drop(connection);
        self.journal.checkpoint_committed_head()?;
        Ok(())
    }

    pub fn commit_petal_registration(
        &self,
        request: &PetalRegistrationCommitRequest,
    ) -> Result<PetalRegistration, AuthorityError> {
        let _barrier = self.lock_authorization_barrier()?;
        let mut connection = self.lock_for_mutation()?;
        let attempt = read_attempt(
            &connection,
            "operation_id=?1",
            [request.operation_id.as_str()],
        )?
        .ok_or_else(invalid_missing)?;
        self.validate_attempt(&attempt)?;
        self.validate_registration_receipt(&attempt.terms, &request.ceremony_receipt)?;
        if let Some(stored) = &attempt.receipt {
            if stored != &request.ceremony_receipt {
                return Err(conflict());
            }
        }
        if let Some(record) = attempt.record {
            return Ok(record);
        }
        if !matches!(attempt.state.as_str(), "prepared" | "completed") {
            return Err(conflict());
        }
        let mut record = PetalRegistration {
            terms: attempt.terms,
            approved_routes: attempt.request.requested_routes,
            ceremony_receipt: request.ceremony_receipt.clone(),
            registration_digest: Digest32::from_bytes([0; 32]),
        };
        record.registration_digest = record.digest().map_err(invalid)?;
        let transaction = connection.transaction()?;
        transaction.execute("UPDATE petal_registration_attempts SET state='committed',receipt_jcs=?2,record_jcs=?3 WHERE operation_id=?1", params![request.operation_id.as_str(),canonical(&record.ceremony_receipt)?,canonical(&record)?])?;
        self.journal.append_external_audit(
            &transaction,
            "petal.registration_committed",
            &serde_json::json!({"registration": record}),
        )?;
        transaction.commit()?;
        drop(connection);
        self.journal.checkpoint_committed_head()?;
        Ok(record)
    }

    pub fn petal_registration(
        &self,
        package_hash: &Digest32,
    ) -> Result<Option<PetalRegistration>, AuthorityError> {
        let connection = self.lock()?;
        let attempt = read_attempt(
            &connection,
            "enrollment_digest=?1 AND package_hash=?2 AND state='committed'",
            [self.enrollment_digest.as_str(), package_hash.as_str()],
        )?;
        attempt
            .map(|attempt| {
                self.validate_attempt(&attempt)?;
                attempt.record.ok_or_else(invalid_missing)
            })
            .transpose()
    }

    pub(crate) fn petal_registration_proposal(
        &self,
        operation: &OperationId,
    ) -> Result<(PetalRegistrationPrepareRequest, PetalRegistrationTerms), AuthorityError> {
        let connection = self.lock()?;
        let attempt = read_attempt(&connection, "operation_id=?1", [operation.as_str()])?
            .ok_or_else(invalid_missing)?;
        self.validate_attempt(&attempt)?;
        Ok((attempt.request, attempt.terms))
    }

    fn validate_attempt(&self, attempt: &Attempt) -> Result<(), AuthorityError> {
        let canonical_request =
            canonical_petal_registration_request(&attempt.request).map_err(invalid)?;
        let terms = &attempt.terms;
        terms.validate_shape().map_err(invalid)?;
        if canonical_request != attempt.request
            || terms.enrollment_digest != self.enrollment_digest
            || terms.operation_id != attempt.request.operation_id
            || terms.owner_wallet_id != attempt.request.owner_wallet_id
            || terms.package_hash.as_str() != attempt.request.evidence.package_hash
            || terms.manifest_digest
                != petal_registration_manifest_digest(&attempt.request.evidence.manifest_utf8)
                    .map_err(invalid)?
            || terms.permissions_digest
                != petal_registration_permissions_digest(&attempt.request.requested_routes)
                    .map_err(invalid)?
        {
            return Err(invalid_missing());
        }
        let expected_shape = match attempt.state.as_str() {
            "prepared" | "abandoned" => attempt.receipt.is_none() && attempt.record.is_none(),
            "completed" => attempt.receipt.is_some() && attempt.record.is_none(),
            "committed" => attempt.receipt.is_some() && attempt.record.is_some(),
            _ => false,
        };
        if !expected_shape {
            return Err(invalid_missing());
        }
        if let Some(receipt) = &attempt.receipt {
            self.validate_registration_receipt(terms, receipt)?;
        }
        if let Some(record) = &attempt.record {
            if record.terms != *terms
                || record.approved_routes != attempt.request.requested_routes
                || Some(&record.ceremony_receipt) != attempt.receipt.as_ref()
                || record.registration_digest != record.digest().map_err(invalid)?
                || attempt.state != "committed"
            {
                return Err(invalid_missing());
            }
        } else if attempt.state == "committed" {
            return Err(invalid_missing());
        }
        Ok(())
    }

    fn validate_registration_receipt(
        &self,
        terms: &PetalRegistrationTerms,
        receipt: &PetalRegistrationReceipt,
    ) -> Result<(), AuthorityError> {
        receipt
            .validate_binding(terms, &self.authority_edge_digest)
            .map_err(invalid)?;
        if terms.enrollment_digest != self.enrollment_digest
            || receipt.signer_key_id != self.ceremony_key_id
        {
            return Err(invalid_missing());
        }
        let signature =
            Signature::from_slice(&receipt.signer_signature.decode()).map_err(invalid)?;
        self.ceremony_key
            .verify_strict(&receipt.signature_message().map_err(invalid)?, &signature)
            .map_err(invalid)
    }
}

fn read_attempt(
    connection: &Connection,
    predicate: &str,
    args: impl rusqlite::Params,
) -> Result<Option<Attempt>, AuthorityError> {
    let encoded = connection.query_row(
        &format!("SELECT operation_id,enrollment_digest,package_hash,request_jcs,terms_jcs,state,receipt_jcs,record_jcs FROM petal_registration_attempts WHERE {predicate}"), args,
        |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?, row.get::<_,String>(2)?, row.get::<_,String>(3)?, row.get::<_,String>(4)?, row.get::<_,String>(5)?, row.get::<_,Option<String>>(6)?, row.get::<_,Option<String>>(7)?)),
    ).optional()?;
    encoded.map(|(operation,enrollment,package,request,terms,state,receipt,record)| {
        let terms: PetalRegistrationTerms = serde_json::from_str(&terms).map_err(storage)?;
        let lineage: Option<String> = connection.query_row(
            "SELECT lineage_id FROM petal_registration_identities WHERE enrollment_digest=?1 AND package_hash=?2",
            params![enrollment,package], |row| row.get(0),
        ).optional()?;
        if operation != terms.operation_id.as_str() || enrollment != terms.enrollment_digest.as_str()
            || package != terms.package_hash.as_str() || lineage.as_ref() != Some(&terms.lineage_id) {
            return Err(invalid_missing());
        }
        Ok(Attempt {
            request: serde_json::from_str(&request).map_err(storage)?, terms, state,
            receipt: receipt.map(|value| serde_json::from_str(&value).map_err(storage)).transpose()?,
            record: record.map(|value| serde_json::from_str(&value).map_err(storage)).transpose()?,
        })
    }).transpose()
}
fn canonical(value: &impl Serialize) -> Result<String, AuthorityError> {
    serde_jcs::to_string(value).map_err(storage)
}
fn invalid(error: impl std::fmt::Display) -> AuthorityError {
    denied("PETAL_REGISTRATION_INVALID", error.to_string())
}
fn invalid_missing() -> AuthorityError {
    invalid("registration evidence is absent or does not match current custody enrollment")
}
fn conflict() -> AuthorityError {
    denied(
        "OPERATION_ID_CONFLICT",
        "package registration conflicts with the reserved or owner-approved proposal; use a new operation after cancelling an unapproved attempt",
    )
}
fn random_lineage() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut output = String::from("pln1_");
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    output
}
