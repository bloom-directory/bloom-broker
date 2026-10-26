//! One-operation Pump approval: independently read the actual message and
//! bind every byte except its refreshable recent blockhash to owner review.

#[cfg(test)]
mod tests;

use crate::message_review::{MessageField, MessageReview};
use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalSelector, CryptoSuite, MachineSignRequest, ProtocolError,
    ProtocolErrorCode, SealedApprovalTerms, SigningPayloads,
};
use bloom_solana_clear_signing::{
    Pubkey,
    inspection::{self, MessageReading},
};
use sha2::{Digest, Sha256};

pub(crate) const BINDING_FIELD: &str = "Transaction binding (recent blockhash excluded)";

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::SelectorMismatch, message)
}

pub(crate) fn is_scope(terms: &SealedApprovalTerms) -> bool {
    matches!(&terms.selector, ApprovalSelector::Petal { allowed_operation_classes, route_grants, .. }
        if allowed_operation_classes.iter().chain(route_grants.iter().flat_map(|g| &g.allowed_operation_classes))
            .any(|c| bloom_broker_api::pumpfun_review_required(c.as_str())))
}

fn validate_scope(terms: &SealedApprovalTerms, class: &str) -> Result<(), ProtocolError> {
    let ApprovalSelector::Petal {
        allowed_operation_classes,
        route_grants,
        ..
    } = &terms.selector
    else {
        return Err(invalid(
            "Pump transaction review requires its blockhash-refresh scope",
        ));
    };
    if !bloom_broker_api::pumpfun_review_required(class)
        || allowed_operation_classes.len() != 1
        || allowed_operation_classes[0].as_str() != class
        || !route_grants.is_empty()
        || terms.allowed_crypto_suites != [CryptoSuite::Ed25519Message]
        || terms.limits.max_operations.get() != 1
        || terms.limits.max_signatures.get() != 1
    {
        return Err(invalid(
            "Pump transaction scope must bind one class, account, operation and Ed25519 signature",
        ));
    }
    Ok(())
}

fn reading(bytes: &[u8], signer: Pubkey) -> Result<MessageReading, ProtocolError> {
    let reading =
        inspection::inspect(bytes).map_err(|e| invalid(format!("Invalid Solana review: {e}")))?;
    if reading.fee_payer != signer {
        return Err(invalid(
            "Solana fee payer differs from the selected signing account",
        ));
    }
    Ok(reading)
}

pub(crate) fn prepare(
    request: &ApprovalPrepareRequest,
    signer: Pubkey,
) -> Result<MessageReview, ProtocolError> {
    let claim = request
        .petal_use_claim
        .as_ref()
        .ok_or_else(|| invalid("Pump review requires its Petal claim"))?;
    validate_scope(&request.terms, claim.operation_class.as_str())?;
    if claim.crypto_suite != CryptoSuite::Ed25519Message
        || request.message_review_payloads.len() != 1
        || !request.evm_review_payloads.is_empty()
        || !request.safe_review_payloads.is_empty()
    {
        return Err(invalid(
            "Pump review requires one complete Solana message; upgrade Bloom Machine",
        ));
    }
    let bytes = request.message_review_payloads[0].decode();
    let reading = reading(&bytes, signer)?;
    let mut batch = Sha256::new();
    batch.update(b"bloom.petal.payload-batch.v1\0");
    batch.update(1u64.to_be_bytes());
    batch.update((bytes.len() as u64).to_be_bytes());
    batch.update(&bytes);
    let expected_hash = bloom_broker_api::Digest32::new(reading.payload_sha256.clone())
        .map_err(|e| invalid(e.to_string()))?;
    if claim.ordered_hashes != [expected_hash]
        || claim.payload_digest != bloom_broker_api::Digest32::from_bytes(batch.finalize().into())
    {
        return Err(invalid(
            "Pump review message differs from the prepared claim hash",
        ));
    }
    let requested_priority_fee = priority_fee_budget(&reading);
    let mut fields = vec![
        MessageField {
            path: BINDING_FIELD.into(),
            value: reading.blockhash_independent_sha256.clone(),
        },
        MessageField {
            path: "Recent blockhash (refreshable)".into(),
            value: reading.recent_blockhash,
        },
        MessageField {
            path: "Message SHA-256".into(),
            value: reading.payload_sha256,
        },
    ];
    if let Some(lamports) = requested_priority_fee {
        let amount = lamports.to_string();
        fields.push(MessageField {
            path: "Requested priority fee ceiling".into(),
            value: format!(
                "{amount} lamports ({} SOL); base and program fees are additional",
                sol_display(&amount)
            ),
        });
    }
    for (index, signer) in reading.signers.iter().enumerate() {
        fields.push(MessageField {
            path: format!("Required signer {}", index + 1),
            value: signer.to_string(),
        });
    }
    for (index, instruction) in reading.instructions.iter().enumerate() {
        let prefix = format!("Instruction {}", index + 1);
        fields.push(MessageField {
            path: prefix.clone(),
            value: instruction
                .name
                .clone()
                .unwrap_or_else(|| "Undecoded instruction".into()),
        });
        fields.push(MessageField {
            path: format!("{prefix} · Program"),
            value: instruction.program.to_string(),
        });
        for account in &instruction.accounts {
            let address = account.address.map(|a| a.to_string()).unwrap_or_else(|| {
                format!(
                    "Unresolved lookup {}",
                    account.lookup.as_deref().unwrap_or("unknown")
                )
            });
            fields.push(MessageField {
                path: format!("{prefix} · {} (index {})", account.role, account.index),
                value: format!(
                    "{address} · {} · {}",
                    if account.signer {
                        "signer"
                    } else {
                        "not signer"
                    },
                    if account.writable {
                        "writable"
                    } else {
                        "read-only"
                    }
                ),
            });
        }
        for argument in &instruction.fields {
            let native = (instruction.program.to_string() == "11111111111111111111111111111111"
                && argument.name == "lamports")
                || (matches!(
                    instruction.name.as_deref(),
                    Some("Pump · buy" | "Pump · sell" | "Pump · buy_exact_sol_in")
                ) && matches!(
                    argument.name.as_str(),
                    "max_sol_cost" | "min_sol_output" | "spendable_sol_in"
                ));
            let (label, value) = if native {
                (
                    argument.name.replace('_', " "),
                    format!(
                        "{} lamports ({} SOL)",
                        argument.value,
                        sol_display(&argument.value)
                    ),
                )
            } else if matches!(
                argument.name.as_str(),
                "amount"
                    | "base_amount_out"
                    | "base_amount_in"
                    | "min_tokens_out"
                    | "min_base_amount_out"
                    | "max_quote_amount_in"
                    | "min_quote_amount_out"
                    | "spendable_quote_in"
            ) {
                (
                    format!("{} (raw units)", argument.name.replace('_', " ")),
                    argument.value.clone(),
                )
            } else {
                (argument.name.replace('_', " "), argument.value.clone())
            };
            fields.push(MessageField {
                path: format!("{prefix} · {label}"),
                value,
            });
        }
        fields.push(MessageField {
            path: format!("{prefix} · Exact instruction bytes"),
            value: instruction.data_hex.clone(),
        });
        if let Some(warning) = &instruction.warning {
            fields.push(MessageField {
                path: format!("{prefix} · Reading limit"),
                value: warning.clone(),
            });
        }
    }
    if fields.len() > 256 {
        return Err(invalid(
            "Solana transaction exceeds its owner review field bound",
        ));
    }
    let mut warnings = reading.warnings;
    warnings.push("Petal value limits and quotes remain MachineAsserted. Unknown token amounts retain raw units.".into());
    Ok(MessageReview {
        kind: "solana_message".into(),
        title: "Approve a Solana transaction".into(),
        signer: signer.to_string(),
        payload_keccak: String::new(),
        domain: vec![],
        fields,
        payment: None,
        venue_asset: None,
        collateral_asset: None,
        warnings,
    })
}

fn sol_display(lamports: &str) -> String {
    let value = lamports
        .parse::<u128>()
        .expect("decoded native amounts and fee products fit u128");
    let whole = value / 1_000_000_000;
    let fraction = value % 1_000_000_000;
    if fraction == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{}", format!("{fraction:09}").trim_end_matches('0'))
    }
}

fn priority_fee_budget(reading: &MessageReading) -> Option<u128> {
    let mut limits = Vec::new();
    let mut prices = Vec::new();
    for instruction in &reading.instructions {
        if instruction.name.as_deref() == Some("Compute budget · unit limit") {
            limits.push(instruction.fields.first()?.value.parse::<u128>().ok()?);
        }
        if instruction.name.as_deref() == Some("Compute budget · unit price") {
            prices.push(instruction.fields.first()?.value.parse::<u128>().ok()?);
        }
    }
    if limits.len() != 1 || prices.len() != 1 {
        return None;
    }
    Some((limits[0] * prices[0]).div_ceil(1_000_000))
}

pub(crate) fn verify_use(
    terms: &SealedApprovalTerms,
    request: &MachineSignRequest,
    signer: Pubkey,
    approved: &MessageReview,
) -> Result<(), ProtocolError> {
    let claim = request
        .petal_use_claim
        .as_ref()
        .ok_or_else(|| invalid("Pump signing use requires its claim"))?;
    validate_scope(terms, claim.operation_class.as_str())?;
    if request.crypto_suite != CryptoSuite::Ed25519Message
        || claim.crypto_suite != request.crypto_suite
    {
        return Err(invalid(
            "Pump signing use requires Ed25519 over the raw message",
        ));
    }
    let payload = match &request.payloads {
        SigningPayloads::Single { payload } => payload,
        SigningPayloads::Batch { children } if children.len() == 1 => &children[0],
        _ => return Err(invalid("Pump signing use requires exactly one message")),
    };
    let actual = reading(&payload.decode(), signer)?;
    let bindings: Vec<_> = approved
        .fields
        .iter()
        .filter(|f| f.path == BINDING_FIELD)
        .collect();
    if approved.kind != "solana_message"
        || approved.signer != signer.to_string()
        || bindings.len() != 1
        || bindings[0].value != actual.blockhash_independent_sha256
    {
        return Err(invalid(
            "Solana transaction differs from its owner review; prepare a new approval",
        ));
    }
    Ok(())
}
