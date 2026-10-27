//! Versioned, Broker-only USD economics. No pricing fields cross custody edge.
use crate::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const SESSION_QUOTE_MAX_AGE_MS: u64 = 900_000;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPricedAsset {
    pub asset: AssetId,
    pub decimals: u8,
    pub coingecko_platform: Option<String>,
    pub coingecko_id: Option<String>,
    pub defillama_id: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMemberAllocation {
    pub scope_digest: Digest32,
    pub limits: ApprovalLimits,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionUsdPolicy {
    pub schema_version: u16,
    pub budget_nonce: RequestNonce,
    pub member_scope_digests: Vec<Digest32>,
    pub member_templates: Vec<SealedApprovalTerms>,
    pub member_backstop_allocations: Vec<SessionMemberAllocation>,
    pub assets: Vec<SessionPricedAsset>,
    pub pricing_policy_digest: Digest32,
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
    pub schema_version: u16,
    pub payload_contexts: Vec<SessionPayloadContext>,
    pub permission_effect: SessionPermissionEffect,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPriceQuote {
    pub asset: AssetId,
    pub price_usd: String,
    pub provider: Token,
    pub timestamp_ms: DecimalU64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionValuation {
    pub accepted_at_ms: DecimalU64,
    pub quotes: Vec<SessionPriceQuote>,
    pub usd_microdollars: DecimalU256,
}
pub fn session_pricing_policy_digest() -> Digest32 {
    Digest32::from_bytes(Sha256::digest(b"bloom-session-pricing/v1:coingecko-keyless,defillama-keyless;max-age-ms=900000;future-skew-ms=5000;gross;ceil-micro-usd").into())
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
impl SessionUsdPolicy {
    pub fn validate(&self, limits: &ApprovalLimits) -> Result<(), ProtocolError> {
        if self.schema_version != 2
            || self.pricing_policy_digest != session_pricing_policy_digest()
            || self.assets.is_empty()
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
            return Err(invalid("invalid versioned USD session policy"));
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
                return Err(invalid(
                    "asset metadata or provider mapping is not approved",
                ));
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
/// Release-trusted deployment mappings. Unknown identities require exact approval.
pub fn approved_session_asset(asset: &AssetId) -> Option<SessionPricedAsset> {
    let chain = asset.chain.as_str();
    let (platform, llama, native, decimals) = match chain {
        "evm-1" => ("ethereum", "ethereum", "ethereum", 18),
        "evm-137" => ("polygon-pos", "polygon", "polygon-ecosystem-token", 18),
        "evm-8453" => ("base", "base", "ethereum", 18),
        "evm-42161" => ("arbitrum-one", "arbitrum", "ethereum", 18),
        "evm-56" => ("binance-smart-chain", "bsc", "binancecoin", 18),
        "evm-100" => ("xdai", "xdai", "xdai", 18),
        "evm-43114" => ("avalanche", "avax", "avalanche-2", 18),
        "evm-59144" => ("linea", "linea", "ethereum", 18),
        "evm-10" => ("optimistic-ethereum", "optimism", "ethereum", 18),
        // Network token encodes the pinned mainnet genesis, never an arbitrary RPC URL.
        "solana-mainnet" => {
            let (id, decimals) = match asset.asset.as_str() {
                "native" => (Some("solana".to_owned()), 9),
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => (None, 6),
                "So11111111111111111111111111111111111111112" => (None, 9),
                _ => return None,
            };
            return Some(SessionPricedAsset {
                asset: asset.clone(),
                decimals,
                coingecko_platform: if id.is_some() {
                    None
                } else {
                    Some("solana".into())
                },
                coingecko_id: id,
                defillama_id: format!(
                    "solana:{}",
                    if asset.asset == "native" {
                        "So11111111111111111111111111111111111111112"
                    } else {
                        &asset.asset
                    }
                ),
            });
        }
        _ => return None,
    };
    if asset.asset == "native" {
        return Some(SessionPricedAsset {
            asset: asset.clone(),
            decimals,
            coingecko_platform: None,
            coingecko_id: Some(native.into()),
            defillama_id: format!("coingecko:{native}"),
        });
    }
    if asset.asset.len() != 42
        || !asset.asset.starts_with("0x")
        || asset.asset[2..]
            .bytes()
            .any(|c| !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let chain_id = chain.strip_prefix("evm-")?.parse::<u64>().ok()?;
    let decimals = if chain_id == 137 && asset.asset == "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb"
    {
        6
    } else {
        known_tokens()
            .iter()
            .find(|t| t.chain_id == chain_id && t.address == asset.asset)?
            .decimals
    };
    Some(SessionPricedAsset {
        asset: asset.clone(),
        decimals,
        coingecko_platform: Some(platform.into()),
        coingecko_id: None,
        defillama_id: format!("{llama}:{}", asset.asset),
    })
}
/// Decimal strings are exact rational numbers; floats never enter accounting.
pub fn session_usd_charge(
    amount: &DecimalU256,
    decimals: u8,
    price: &str,
) -> Result<DecimalU256, ProtocolError> {
    use num_bigint::BigUint;
    use std::str::FromStr;
    if price.len() > 128 || decimals > 77 {
        return Err(invalid("price bounds exceeded"));
    }
    let mut parts = price.split('.');
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some()
        || whole.is_empty()
        || fraction.len() > 36
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|c| c.is_ascii_digit())
    {
        return Err(invalid("invalid positive decimal price"));
    }
    let p =
        BigUint::from_str(&format!("{whole}{fraction}")).map_err(|_| invalid("invalid price"))?;
    if p == BigUint::from(0u8) {
        return Err(invalid("zero price"));
    }
    let denominator = BigUint::from(10u8).pow(decimals as u32 + fraction.len() as u32);
    let n = BigUint::from_str(amount.as_str()).map_err(|_| invalid("invalid amount"))?
        * p
        * BigUint::from(1_000_000u64);
    DecimalU256::parse(((n + &denominator - BigUint::from(1u8)) / denominator).to_string())
        .map_err(|_| invalid("USD charge overflow"))
}

impl SessionBudget {
    pub fn recorded_quantity(
        &self,
        record: &SessionRecordedUse,
    ) -> Result<DecimalU256, ProtocolError> {
        let Some(policy) = &self.usd_policy else {
            return self.action_nominal_quantity(&record.values);
        };
        let valuation = record
            .valuation
            .as_ref()
            .ok_or_else(|| invalid("USD reservation lacks valuation evidence"))?;
        use num_bigint::BigUint;
        use std::str::FromStr;
        let mut total = BigUint::from(0u8);
        for value in SessionAccounting::canonical_values(&record.values)? {
            let asset = policy
                .assets
                .iter()
                .find(|a| a.asset == value.asset)
                .ok_or_else(|| {
                    ProtocolError::new(
                        ProtocolErrorCode::AssetUnsupported,
                        "asset outside reviewed pricing scope",
                    )
                })?;
            if let Some(cap) = self
                .per_action_value_limits
                .iter()
                .find(|c| c.asset == value.asset)
            {
                if BigUint::from_str(value.amount.as_str()).unwrap()
                    > BigUint::from_str(cap.maximum.as_str()).unwrap()
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::LimitExceededValue,
                        "fixed raw-asset cap exceeded",
                    ));
                }
            }
            let quote = valuation
                .quotes
                .iter()
                .find(|q| q.asset == value.asset)
                .ok_or_else(|| invalid("reservation lacks asset quote"))?;
            if !matches!(quote.provider.as_str(), "coingecko" | "defillama")
                || valuation
                    .quotes
                    .iter()
                    .filter(|q| q.asset == value.asset)
                    .count()
                    != 1
            {
                return Err(invalid("invalid reservation provider/evidence"));
            }
            total += BigUint::from_str(
                session_usd_charge(&value.amount, asset.decimals, &quote.price_usd)?.as_str(),
            )
            .unwrap();
        }
        let result =
            DecimalU256::parse(total.to_string()).map_err(|_| invalid("USD sum overflow"))?;
        if result != valuation.usd_microdollars {
            return Err(invalid(
                "reservation valuation does not match its quantities",
            ));
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPricesRequest {
    pub assets: Vec<AssetId>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPricesResponse {
    pub assets: Vec<SessionPricedAsset>,
    pub quotes: Vec<SessionPriceQuote>,
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
mod tests {
    use super::*;
    fn token(v: &str) -> Token {
        Token::new(v).unwrap()
    }
    fn n(v: &str) -> DecimalU256 {
        DecimalU256::parse(v).unwrap()
    }
    fn digest(v: u8) -> Digest32 {
        Digest32::from_bytes([v; 32])
    }
    fn pusd() -> AssetId {
        AssetId {
            chain: token("evm-137"),
            asset: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
        }
    }
    fn sol() -> AssetId {
        AssetId {
            chain: token("solana-mainnet"),
            asset: "native".into(),
        }
    }
    fn template() -> SealedApprovalTerms {
        SealedApprovalTerms {
            subject: ApprovalSubject::Petal {
                package_hash: digest(1),
                route: "trade".into(),
                agent_id: None,
            },
            wallet_id: token("wallet"),
            key_ref: KeyRef {
                backend: token("local"),
                backend_instance: token("test"),
                locator: "key".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: digest(2),
                derivation: None,
            },
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: ApprovalSelector::Petal {
                package_hash: digest(1),
                route: "trade".into(),
                allowed_operation_classes: vec![token("generic.swap")],
                route_grants: vec![],
                required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(10),
                max_signatures: DecimalU64::new(10),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: vec![],
            },
            activation_mode: ActivationMode::BootBound,
            wallet_revocation_epoch: DecimalU64::new(0),
            policy_version: DecimalU64::new(1),
            policy_digest: digest(3),
            provenance_digest: digest(4),
            request_nonce: RequestNonce::from_bytes([5; 16]),
            issued_at_ms: DecimalU64::new(1),
            not_before_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(10_000_000),
            renewal_of: None,
            session_budget: None,
        }
    }
    fn budget() -> SessionBudget {
        let member = template();
        let scope = session_member_scope_digest(&member).unwrap();
        SessionBudget {
            usd_policy: Some(SessionUsdPolicy {
                schema_version: 2,
                budget_nonce: RequestNonce::from_bytes([6; 16]),
                member_scope_digests: vec![scope.clone()],
                member_templates: vec![member.clone()],
                member_backstop_allocations: vec![SessionMemberAllocation {
                    scope_digest: scope,
                    limits: member.limits.clone(),
                }],
                assets: vec![
                    approved_session_asset(&pusd()).unwrap(),
                    approved_session_asset(&sol()).unwrap(),
                ],
                pricing_policy_digest: session_pricing_policy_digest(),
            }),
            wallet_id: member.wallet_id.clone(),
            policy_version: member.policy_version,
            policy_digest: member.policy_digest.clone(),
            wallet_revocation_epoch: member.wallet_revocation_epoch,
            member_keys: vec![member.key_ref],
            limits: member.limits,
            nominal_asset_scales: vec![],
            nominal_limits: SessionNominalLimits {
                per_action: n("100000000"),
                lifetime: n("200000000"),
                rolling_windows: vec![ValueWindow {
                    maximum: n("100000000"),
                    duration_ms: DecimalU64::new(100),
                }],
            },
            per_action_value_limits: vec![
                SessionValueCeiling {
                    asset: pusd(),
                    maximum: n("100000000"),
                },
                SessionValueCeiling {
                    asset: sol(),
                    maximum: n("10000000000"),
                },
            ],
            not_before_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(10_000_000),
        }
    }
    fn record(values: Vec<(AssetId, &str, &str)>, now: u64) -> SessionRecordedUse {
        let mut amounts = vec![];
        let mut quotes = vec![];
        let mut total = num_bigint::BigUint::from(0u8);
        // Build expected totals independently using the public exact converter;
        // aggregation behavior is exercised by separate duplicate-line cases.
        for (asset, amount, price) in values {
            let metadata = approved_session_asset(&asset).unwrap();
            let charge = session_usd_charge(&n(amount), metadata.decimals, price).unwrap();
            total += charge.as_str().parse::<num_bigint::BigUint>().unwrap();
            amounts.push(SessionAssetAmount {
                asset: asset.clone(),
                amount: n(amount),
            });
            quotes.push(SessionPriceQuote {
                asset,
                price_usd: price.into(),
                provider: token("coingecko"),
                timestamp_ms: DecimalU64::new(now),
            });
        }
        SessionRecordedUse {
            accepted_at_ms: now,
            signature_count: 1,
            values: amounts,
            valuation: Some(SessionValuation {
                accepted_at_ms: DecimalU64::new(now),
                quotes,
                usd_microdollars: n(&total.to_string()),
            }),
        }
    }

    #[test]
    fn exact_usd_conversion_rounds_up_without_float_loss_and_refuses_overflow() {
        for (amount, decimals, price, expected) in [
            ("1000001", 6, "0.999417", "999418"),
            ("1", 18, "2000.123456789012345678901234567890123456", "1"),
            (
                "1000000000000000000",
                18,
                "2000.000000000000000001",
                "2000000001",
            ),
            ("0", 6, "0.999417", "0"),
            ("1000000", 6, "1.000001", "1000001"),
        ] {
            assert_eq!(
                session_usd_charge(&n(amount), decimals, price)
                    .unwrap()
                    .as_str(),
                expected
            );
        }
        for price in ["0", "-1", "NaN", "inf", "1e-8", "1.2.3", "", ".5"] {
            assert!(session_usd_charge(&n("1"), 6, price).is_err(), "{price}");
        }
        assert!(session_usd_charge(&n("1"), 78, "1").is_err());
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert!(session_usd_charge(&n(max), 0, "1").is_err());
    }

    #[test]
    fn duplicate_lines_aggregate_before_rounding_and_cannot_bypass_fixed_raw_caps() {
        let mut b = budget();
        b.validate().unwrap();
        let mut r = record(vec![(pusd(), "1", "0.1")], 1_000_000);
        r.values = vec![
            SessionAssetAmount {
                asset: pusd(),
                amount: n("1"),
            },
            SessionAssetAmount {
                asset: pusd(),
                amount: n("1"),
            },
        ];
        // 2 raw units at 0.1 USD/token is 0.2 microdollars: charge once upward.
        r.valuation.as_mut().unwrap().usd_microdollars = n("1");
        assert_eq!(b.recorded_quantity(&r).unwrap().as_str(), "1");
        b.per_action_value_limits[0].maximum = n("1");
        assert!(b.recorded_quantity(&r).is_err());
        let mut low = record(vec![(pusd(), "1000001", "0.000001")], 1_000_000);
        b.per_action_value_limits[0].maximum = n("1000000");
        assert!(b.recorded_quantity(&low).is_err());
        // Optional Petal raw caps remain optional, but USD pricing still applies.
        b.per_action_value_limits.clear();
        assert_eq!(b.recorded_quantity(&low).unwrap().as_str(), "2");
        low.valuation = None;
        assert!(b.recorded_quantity(&low).is_err());
    }

    #[test]
    fn unknown_assets_bad_metadata_and_missing_prices_never_become_free_or_pegged() {
        let b = budget();
        let r = record(vec![(pusd(), "1000000", "0.999417")], 1_000_000);
        assert_eq!(b.recorded_quantity(&r).unwrap().as_str(), "999417");
        let mut bad = r.clone();
        bad.valuation.as_mut().unwrap().quotes.clear();
        assert!(b.recorded_quantity(&bad).is_err());
        let mut bad = r.clone();
        bad.values[0].asset.asset = "pusd".into();
        assert!(b.recorded_quantity(&bad).is_err());
        let mut bad = r.clone();
        bad.values[0].asset.chain = token("evm-1");
        assert!(b.recorded_quantity(&bad).is_err());
        let mut bad = r.clone();
        bad.valuation.as_mut().unwrap().quotes[0].provider = token("petal");
        assert!(b.recorded_quantity(&bad).is_err());
        let mut bad = r.clone();
        let quote = bad.valuation.as_ref().unwrap().quotes[0].clone();
        bad.valuation.as_mut().unwrap().quotes.push(quote);
        assert!(b.recorded_quantity(&bad).is_err());
        let mut bad = r.clone();
        bad.valuation.as_mut().unwrap().usd_microdollars = n("1000000");
        assert!(b.recorded_quantity(&bad).is_err());
        let mut wrong = b.clone();
        wrong.usd_policy.as_mut().unwrap().assets[0].decimals = 18;
        assert!(wrong.validate().is_err());
        let mut wrong = b.clone();
        wrong.usd_policy.as_mut().unwrap().assets[0].coingecko_id = Some("usd-coin".into());
        assert!(wrong.validate().is_err());
        let mut mint = AssetId {
            chain: token("solana-mainnet"),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
        };
        assert_eq!(approved_session_asset(&mint).unwrap().decimals, 6);
        mint.asset = mint.asset.to_lowercase();
        assert!(approved_session_asset(&mint).is_none());
    }

    #[test]
    fn cross_asset_gross_costs_share_limits_without_repricing_history_or_refunding_proceeds() {
        let mut b = budget();
        let mut first = record(
            vec![(pusd(), "10000000", "1"), (sol(), "200005000", "100")],
            1_000_000,
        );
        assert_eq!(
            first.valuation.as_ref().unwrap().usd_microdollars.as_str(),
            "30000500"
        );
        b.check_reservation(&[], &first).unwrap();
        // Principal and maximum fee are the same native asset; split lines must
        // aggregate once with the same price, not count the fee twice.
        first.values[1].amount = n("200000000");
        first.values.push(SessionAssetAmount {
            asset: sol(),
            amount: n("5000"),
        });
        assert_eq!(b.recorded_quantity(&first).unwrap().as_str(), "30000500");
        let later = record(vec![(pusd(), "10000000", "0.5")], 1_900_001);
        assert_eq!(b.recorded_quantity(&first).unwrap().as_str(), "30000500");
        // Old quote freshness is not rechecked to reset/erase historical usage.
        b.nominal_limits.lifetime = n("35000499");
        assert!(b.check_reservation(&[first.clone()], &later).is_err());
        b.nominal_limits.lifetime = n("35000500");
        b.check_reservation(&[first], &later).unwrap();
        assert!(DecimalU256::parse("-1000000").is_err());
    }

    #[test]
    fn reservation_rechecks_exact_age_future_skew_and_acceptance_delay() {
        let b = budget();
        let mut r = record(vec![(pusd(), "1000000", "1")], 1_000_000);
        r.valuation.as_mut().unwrap().quotes[0].timestamp_ms = DecimalU64::new(100_000);
        b.check_reservation(&[], &r).unwrap();
        r.valuation.as_mut().unwrap().quotes[0].timestamp_ms = DecimalU64::new(99_999);
        assert_eq!(
            b.check_reservation(&[], &r).unwrap_err().code,
            ProtocolErrorCode::PriceStale
        );
        r.valuation.as_mut().unwrap().quotes[0].timestamp_ms = DecimalU64::new(1_005_000);
        b.check_reservation(&[], &r).unwrap();
        r.valuation.as_mut().unwrap().quotes[0].timestamp_ms = DecimalU64::new(1_005_001);
        assert!(b.check_reservation(&[], &r).is_err());
        r.valuation.as_mut().unwrap().quotes[0].timestamp_ms = DecimalU64::new(1_000_000);
        r.valuation.as_mut().unwrap().accepted_at_ms = DecimalU64::new(990_000);
        b.check_reservation(&[], &r).unwrap();
        r.valuation.as_mut().unwrap().accepted_at_ms = DecimalU64::new(989_999);
        assert!(b.check_reservation(&[], &r).is_err());
    }
}
