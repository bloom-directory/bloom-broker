//! Exact-token session scopes and authenticated member commitments.
use crate::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Explicit wallet-policy opt-in to standing reusable approvals. This numeric
/// policy field must remain exactly representable by JSON canonicalization.
/// Approval expiry itself uses DecimalU64(u64::MAX), serialized as a string.
pub const STANDING_APPROVAL_POLICY_LIFETIME_MS: u64 = 9_007_199_254_740_991;

pub const DECLARED_EFFECTS_CAPABILITY: &str = "bloom.declared-effects.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredSpendKind {
    None,
    Bounded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PetalSessionPersona {
    Institutional,
    Trader,
    Degen,
}

/// Owner-reviewed automatic authority. The single zero-spend rate cap is
/// shared by every listed class within one member approval, never multiplied
/// by classes. It is not pooled across other member approvals that share this
/// session budget; token usage follows the shared token budget independently.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalSessionPolicy {
    pub persona: PetalSessionPersona,
    /// Zero-token classes are explicitly network-unrestricted. Index, exact
    /// spending account, package and class still bind every use. Token spend
    /// retains the token policy's network and asset constraints.
    pub zero_spend_classes: Vec<Token>,
    pub zero_spend_rate_limit: Option<SlidingWindow>,
}
impl PetalSessionPolicy {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.persona == PetalSessionPersona::Institutional
            || self.zero_spend_classes.len() > 128
            || self
                .zero_spend_classes
                .iter()
                .enumerate()
                .any(|(i, class)| self.zero_spend_classes[..i].contains(class))
            || self.zero_spend_classes.is_empty() != self.zero_spend_rate_limit.is_none()
            || self
                .zero_spend_rate_limit
                .as_ref()
                .is_some_and(|cap| cap.maximum.get() == 0 || cap.duration_ms.get() == 0)
        {
            return Err(invalid("invalid automatic persona grant"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTokenAsset {
    pub asset: AssetId,
    pub decimals: u8,
    pub symbol: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMemberAllocation {
    pub scope_digest: Digest32,
    pub limits: ApprovalLimits,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTokenPolicy {
    pub schema_version: u16,
    pub budget_nonce: RequestNonce,
    pub member_scope_digests: Vec<Digest32>,
    pub member_templates: Vec<SealedApprovalTerms>,
    pub member_backstop_allocations: Vec<SessionMemberAllocation>,
    pub assets: Vec<SessionTokenAsset>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPermissionEffect {
    None,
    RequiresSeparateApproval,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPayloadContext {
    pub payload_index: u32,
    pub network: Token,
    pub spending_accounts: Vec<KeyRef>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicEffectsV1 {
    pub spend: DeclaredSpendKind,
    pub schema_version: u16,
    pub payload_contexts: Vec<SessionPayloadContext>,
    pub permission_effect: SessionPermissionEffect,
}
/// Excludes the pool and issuance nonce to avoid a circular commitment.
pub fn session_member_scope_digest(terms: &SealedApprovalTerms) -> Result<Digest32, ProtocolError> {
    let mut v = serde_json::to_value(terms).map_err(|e| invalid(&e.to_string()))?;
    let o = v
        .as_object_mut()
        .ok_or_else(|| invalid("invalid member terms"))?;
    for k in [
        "session_budget",
        "request_nonce",
        "issued_at_ms",
        "renewal_of",
    ] {
        o.remove(k);
    }
    let mut h = Sha256::new();
    h.update(b"bloom-session-member/v2");
    h.update(serde_jcs::to_vec(&v).map_err(|e| invalid(&e.to_string()))?);
    Ok(Digest32::from_bytes(h.finalize().into()))
}
fn invalid(s: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, s)
}
impl SessionTokenPolicy {
    pub fn validate(&self, limits: &ApprovalLimits) -> Result<(), ProtocolError> {
        if self.schema_version != 3
            || self.assets.len() > 128
            || self.member_scope_digests.is_empty()
            || self.member_templates.len() != self.member_scope_digests.len()
            || self.member_scope_digests.len() > 128
            || self.member_backstop_allocations.len() != self.member_scope_digests.len()
            || self
                .member_scope_digests
                .windows(2)
                .any(|w| w[0].as_str() >= w[1].as_str())
        {
            return Err(invalid("invalid versioned token session policy"));
        }
        let mut operations = 0u64;
        let mut signatures = 0u64;
        for (i, template) in self.member_templates.iter().enumerate() {
            if template.session_budget.is_some()
                || session_member_scope_digest(template)? != self.member_scope_digests[i]
                || template.limits != self.member_backstop_allocations[i].limits
            {
                return Err(invalid(
                    "reviewed member template differs from scope/allocation",
                ));
            }
        }
        for (i, a) in self.member_backstop_allocations.iter().enumerate() {
            crate::approval::validate_limits(&a.limits)?;
            if a.scope_digest != self.member_scope_digests[i]
                || a.limits.max_operations.get() == 0
                || a.limits.max_signatures.get() == 0
            {
                return Err(invalid("invalid member backstop allocation"));
            }
            operations = operations
                .checked_add(a.limits.max_operations.get())
                .ok_or_else(|| invalid("operation allocation overflow"))?;
            signatures = signatures
                .checked_add(a.limits.max_signatures.get())
                .ok_or_else(|| invalid("signature allocation overflow"))?;
        }
        if operations > limits.max_operations.get() || signatures > limits.max_signatures.get() {
            return Err(invalid("member allocations exceed shared backstop"));
        }
        for signature in [false, true] {
            let pool = if signature {
                &limits.signature_rate_limits
            } else {
                &limits.operation_rate_limits
            };
            for allocation in &self.member_backstop_allocations {
                let member = if signature {
                    &allocation.limits.signature_rate_limits
                } else {
                    &allocation.limits.operation_rate_limits
                };
                if member.len() != pool.len()
                    || member
                        .iter()
                        .any(|m| !pool.iter().any(|p| p.duration_ms == m.duration_ms))
                {
                    return Err(invalid(
                        "member rate windows must match reviewed pool windows",
                    ));
                }
            }
            for window in pool {
                let mut total = 0u64;
                for allocation in &self.member_backstop_allocations {
                    let member = if signature {
                        &allocation.limits.signature_rate_limits
                    } else {
                        &allocation.limits.operation_rate_limits
                    };
                    let rate = member
                        .iter()
                        .find(|m| m.duration_ms == window.duration_ms)
                        .ok_or_else(|| invalid("member rate allocation missing"))?;
                    total = total
                        .checked_add(rate.maximum.get())
                        .ok_or_else(|| invalid("rate allocation overflow"))?;
                }
                if total > window.maximum.get() {
                    return Err(invalid("member rate allocations exceed pool backstop"));
                }
            }
        }
        for (i, a) in self.assets.iter().enumerate() {
            if approved_session_asset(&a.asset).as_ref() != Some(a)
                || self.assets[..i].iter().any(|x| x.asset == a.asset)
            {
                return Err(invalid("token display metadata is not approved"));
            }
        }
        Ok(())
    }
    pub fn validate_member(&self, terms: &SealedApprovalTerms) -> Result<(), ProtocolError> {
        let digest = session_member_scope_digest(terms)?;
        if !self.member_templates.iter().any(|t| {
            t.request_nonce == terms.request_nonce
                && session_member_scope_digest(t).is_ok_and(|d| d == digest)
        }) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "member issuance nonce differs from reviewed template",
            ));
        }
        if !self
            .member_backstop_allocations
            .iter()
            .any(|a| a.scope_digest == digest && a.limits == terms.limits)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "session member scope/backstop differs from reviewed allocation",
            ));
        }
        Ok(())
    }
}
/// Trusted display metadata only. Raw amounts never depend on a price service.
pub fn approved_session_asset(asset: &AssetId) -> Option<SessionTokenAsset> {
    let (decimals, symbol) = if asset.chain.as_str() == "solana-mainnet" {
        match asset.asset.as_str() {
            "native" | "So11111111111111111111111111111111111111112" => (9, "SOL"),
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => (6, "USDC"),
            _ => return None,
        }
    } else {
        let id = asset
            .chain
            .as_str()
            .strip_prefix("evm-")?
            .parse::<u64>()
            .ok()?;
        if asset.asset == "native" {
            (
                18,
                match id {
                    1 | 8453 | 42161 | 59144 | 10 | 31337 => "ETH",
                    137 => "POL",
                    56 => "BNB",
                    100 => "XDAI",
                    43114 => "AVAX",
                    999 => "HYPE",
                    _ => return None,
                },
            )
        } else {
            let token = known_tokens()
                .iter()
                .find(|t| t.chain_id == id && t.address == asset.asset)?;
            (token.decimals, token.symbol.as_str())
        }
    };
    Some(SessionTokenAsset {
        asset: asset.clone(),
        decimals,
        symbol: symbol.into(),
    })
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStopRequest {
    pub budget_id: Digest32,
    pub operation_id: OperationId,
    pub reason: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStopResponse {
    pub budget_id: Digest32,
    pub revoked: Vec<Digest32>,
    pub pending: Vec<Digest32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPoolState {
    Pending,
    Active,
    Stopped,
    Expired,
}
pub fn session_native_claim_digests(
    use_: &SystemSessionUse,
) -> Result<(Digest32, Digest32), ProtocolError> {
    Ok((
        Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(use_).map_err(|e| invalid(&e.to_string()))?).into(),
        ),
        Digest32::from_bytes(
            Sha256::digest(b"bloom-broker-native-transfer-verification/v1").into(),
        ),
    ))
}

#[cfg(test)]
mod standing_policy_tests {
    use super::*;
    #[test]
    fn standing_policy_opt_in_survives_json_canonicalization_exactly() {
        let value = serde_json::json!({"maximum_approval_lifetime_ms":STANDING_APPROVAL_POLICY_LIFETIME_MS});
        let canonical = serde_jcs::to_vec(&value).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(
            decoded["maximum_approval_lifetime_ms"].as_u64(),
            Some(STANDING_APPROVAL_POLICY_LIFETIME_MS)
        );
    }
}

#[cfg(test)]
mod declaration_tests {
    use super::*;
    #[test]
    fn explicit_declaration_and_persona_cap_are_required() {
        let raw = serde_json::json!({"schema_version":1,"payload_contexts":[],"permission_effect":"none"});
        assert!(serde_json::from_value::<EconomicEffectsV1>(raw).is_err());
        let cap = SlidingWindow {
            maximum: DecimalU64::new(60),
            duration_ms: DecimalU64::new(3_600_000),
        };
        let mut policy = PetalSessionPolicy {
            persona: PetalSessionPersona::Trader,
            zero_spend_classes: vec![Token::new("example.login").unwrap()],
            zero_spend_rate_limit: Some(cap),
        };
        policy.validate().unwrap();
        policy.persona = PetalSessionPersona::Institutional;
        assert!(policy.validate().is_err());
        policy.persona = PetalSessionPersona::Degen;
        policy.zero_spend_rate_limit = None;
        assert!(policy.validate().is_err());
    }
    #[test]
    fn legacy_native_selector_is_not_an_alias() {
        assert!(
            serde_json::from_value::<ApprovalSelector>(
                serde_json::json!({"kind":"system_session","scope":{}})
            )
            .is_err()
        );
    }
}
