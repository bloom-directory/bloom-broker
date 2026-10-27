//! Owner-reviewed session scopes and exact asset-unit accounting.
use crate::{
    ApprovalLimits, AssetId, DecimalU64, DecimalU256, Digest32, KeyRef, PolicyDestination,
    ProtocolError, ProtocolErrorCode, Token,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemSessionAction {
    NativeTransfer,
    Erc20Transfer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemSessionChain {
    Evm { chain: Token, chain_id: DecimalU64 },
    Solana { chain: Token, genesis_hash: String },
}
impl SystemSessionChain {
    pub fn chain(&self) -> &Token {
        match self {
            Self::Evm { chain, .. } | Self::Solana { chain, .. } => chain,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionValueCeiling {
    pub asset: AssetId,
    pub maximum: DecimalU256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSessionScope {
    pub component_id: Token,
    pub actions: Vec<SystemSessionAction>,
    pub chains: Vec<SystemSessionChain>,
    pub destinations: Vec<PolicyDestination>,
    pub tokens: Vec<AssetId>,
    pub per_action_value_limits: Vec<SessionValueCeiling>,
}
impl SystemSessionScope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.component_id.as_str() != "bloom-machine"
            || self.actions.is_empty()
            || self.actions.len() > 2
            || self.chains.is_empty()
            || self.chains.len() > 64
            || self.destinations.is_empty()
            || self.destinations.len() > 256
            || self.per_action_value_limits.is_empty()
            || self.per_action_value_limits.len() > 128
            || self
                .actions
                .iter()
                .enumerate()
                .any(|(i, a)| self.actions[..i].contains(a))
            || self.chains.iter().any(|c| match c {
                SystemSessionChain::Evm { chain, chain_id } => {
                    !matches!(chain_id.get(), 1 | 137 | 31337)
                        || chain.as_str() != format!("evm-{}", chain_id.get())
                }
                SystemSessionChain::Solana {
                    chain,
                    genesis_hash,
                } => {
                    chain.as_str() != "solana-mainnet"
                        || genesis_hash != "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
                        || self.actions != [SystemSessionAction::NativeTransfer]
                        || self.tokens.iter().any(|t| t.chain == *chain)
                }
            })
            || self
                .destinations
                .iter()
                .any(|d| !self.chains.iter().any(|c| c.chain() == &d.chain))
            || self
                .chains
                .iter()
                .enumerate()
                .any(|(i, c)| self.chains[..i].contains(c))
            || self
                .tokens
                .iter()
                .enumerate()
                .any(|(i, t)| self.tokens[..i].contains(t))
            || self
                .per_action_value_limits
                .iter()
                .enumerate()
                .any(|(i, c)| {
                    self.per_action_value_limits[..i]
                        .iter()
                        .any(|p| p.asset == c.asset)
                })
            || self.chains.iter().any(|chain| {
                !self
                    .per_action_value_limits
                    .iter()
                    .any(|cap| cap.asset.chain == *chain.chain() && cap.asset.asset == "native")
            })
            || self.tokens.iter().any(|token| {
                !self
                    .per_action_value_limits
                    .iter()
                    .any(|cap| cap.asset == *token)
            })
            || (self.actions.contains(&SystemSessionAction::Erc20Transfer)
                && self.tokens.is_empty())
            || self
                .per_action_value_limits
                .iter()
                .any(|c| c.maximum.as_str() == "0")
        {
            return Err(invalid("invalid typed System session scope"));
        }
        Ok(())
    }
}

/// The caller's semantic projection. Broker independently reconstructs this
/// from the complete signing preimage; the projection cannot authorize bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSessionUse {
    pub action: SystemSessionAction,
    pub chain: SystemSessionChain,
    pub token: Option<AssetId>,
    pub recipient: String,
    pub amount: DecimalU256,
    pub maximum_fee: DecimalU256,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAssetAmount {
    pub asset: AssetId,
    pub amount: DecimalU256,
}

/// Every member approval signs this complete descriptor. The identifier is
/// derived from it, so a caller cannot reuse a chosen alias with different caps.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_policy: Option<crate::SessionTokenPolicy>,
    pub wallet_id: Token,
    pub policy_version: DecimalU64,
    pub policy_digest: Digest32,
    pub wallet_revocation_epoch: DecimalU64,
    pub member_keys: Vec<KeyRef>,
    pub limits: ApprovalLimits,
    /// Includes separately stated native-fee/transfer caps. Unknown assets
    /// always require their own explicitly reviewed allowance.
    pub per_action_value_limits: Vec<SessionValueCeiling>,
    pub not_before_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
}
impl SessionBudget {
    pub fn budget_id(&self) -> Result<Digest32, ProtocolError> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"bloom-session-budget/v1");
        h.update(
            serde_jcs::to_vec(self)
                .map_err(|_| invalid("session budget cannot be canonicalized"))?,
        );
        Ok(Digest32::from_bytes(h.finalize().into()))
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.member_keys.is_empty()
            || self.member_keys.len() > 128
            || self.expires_at_ms.get() <= self.not_before_ms.get()
            || self.limits.max_operations.get() == 0
            || self.limits.max_signatures.get() == 0
            || self.per_action_value_limits.is_empty()
            || self.per_action_value_limits.len() > 128
            || self
                .per_action_value_limits
                .iter()
                .enumerate()
                .any(|(i, s)| {
                    s.maximum.as_str() == "0"
                        || self.per_action_value_limits[..i]
                            .iter()
                            .any(|x| x.asset == s.asset)
                })
        {
            return Err(invalid("invalid immutable session budget"));
        }
        crate::approval::validate_limits(&self.limits)?;
        if let Some(policy) = &self.token_policy {
            policy.validate(&self.limits)?;
            if policy.assets.len() != self.per_action_value_limits.len()
                || policy.assets.len() != self.limits.value_limits.len()
                || policy.assets.iter().any(|a| {
                    !self
                        .per_action_value_limits
                        .iter()
                        .any(|v| v.asset == a.asset)
                        || !self.limits.value_limits.iter().any(|v| v.asset == a.asset)
                })
            {
                return Err(invalid(
                    "every reviewed token needs independent action and rolling limits",
                ));
            }
        }
        if self
            .member_keys
            .iter()
            .enumerate()
            .any(|(i, k)| self.member_keys[..i].contains(k))
        {
            return Err(invalid("duplicate session member key"));
        }
        for k in &self.member_keys {
            k.validate()?;
        }
        Ok(())
    }
}

/// Authenticated Broker projection consumed by Signer's parser-free backstop.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAccounting {
    pub system_use: Option<SystemSessionUse>,
    pub values: Vec<SessionAssetAmount>,
    pub budget_id: Option<Digest32>,
}
fn invalid(message: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, message)
}

impl SessionAccounting {
    pub fn digest(&self) -> Digest32 {
        let bytes = serde_jcs::to_vec(self).expect("closed session accounting serializes");
        Digest32::from_bytes(Sha256::digest(bytes).into())
    }
}
impl SystemSessionUse {
    pub fn accounting(
        &self,
        budget: Option<&SessionBudget>,
    ) -> Result<SessionAccounting, ProtocolError> {
        let chain = self.chain.chain().clone();
        let asset = self.token.clone().unwrap_or_else(|| AssetId {
            chain: chain.clone(),
            asset: "native".into(),
        });
        if asset.chain != chain {
            return Err(invalid("session token belongs to another chain"));
        }
        let mut values = vec![SessionAssetAmount {
            asset,
            amount: self.amount.clone(),
        }];
        if self.maximum_fee.as_str() != "0" {
            values.push(SessionAssetAmount {
                asset: AssetId {
                    chain,
                    asset: "native".into(),
                },
                amount: self.maximum_fee.clone(),
            });
        }
        Ok(SessionAccounting {
            system_use: Some(self.clone()),
            values: SessionAccounting::canonical_values(&values)?,
            budget_id: budget.map(SessionBudget::budget_id).transpose()?,
        })
    }
}

impl SessionBudget {
    /// Aggregate duplicates before checking each exact asset independently.
    pub fn check_action_values(&self, values: &[SessionAssetAmount]) -> Result<(), ProtocolError> {
        use num_bigint::BigUint;
        use std::str::FromStr;
        self.validate()?;
        let mut totals: Vec<(AssetId, BigUint)> = Vec::new();
        for v in values {
            let n = BigUint::from_str(v.amount.as_str())
                .map_err(|_| invalid("invalid session amount"))?;
            if let Some((_, total)) = totals.iter_mut().find(|(a, _)| a == &v.asset) {
                *total += n;
            } else {
                totals.push((v.asset.clone(), n));
            }
        }
        for (asset, amount) in totals {
            let cap = self
                .per_action_value_limits
                .iter()
                .find(|v| v.asset == asset)
                .ok_or_else(|| invalid("asset has no signed per-action session ceiling"))?;
            if amount
                > BigUint::from_str(cap.maximum.as_str())
                    .map_err(|_| invalid("invalid session ceiling"))?
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::LimitExceededValue,
                    "session per-action asset ceiling exceeded",
                ));
            }
            if !self.limits.value_limits.iter().any(|v| v.asset == asset) {
                return Err(invalid("asset has no signed token-unit budget"));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecordedUse {
    pub accepted_at_ms: u64,
    pub signature_count: u64,
    pub values: Vec<SessionAssetAmount>,
}
impl SessionBudget {
    /// Called while the authoritative ledger's write transaction is held.
    /// Reserved, committed and ambiguous records all remain in `previous`.
    pub fn check_reservation(
        &self,
        previous: &[SessionRecordedUse],
        current: &SessionRecordedUse,
    ) -> Result<(), ProtocolError> {
        use num_bigint::BigUint;
        use std::str::FromStr;
        self.validate()?;
        if current.accepted_at_ms < self.not_before_ms.get()
            || current.accepted_at_ms >= self.expires_at_ms.get()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ApprovalExpired,
                "session budget is outside its validity window",
            ));
        }
        if current.signature_count == 0
            || previous.len() as u64 >= self.limits.max_operations.get()
            || previous
                .iter()
                .try_fold(current.signature_count, |n, p| {
                    n.checked_add(p.signature_count)
                })
                .is_none_or(|n| n > self.limits.max_signatures.get())
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::LimitExceededOperations,
                "shared session operation/signature ceiling exceeded",
            ));
        }
        let number = |s: &DecimalU256| {
            BigUint::from_str(s.as_str()).map_err(|_| invalid("invalid budget quantity"))
        };
        self.check_action_values(&current.values)?;
        for cap in &self.limits.value_limits {
            let sum = |cutoff: Option<u64>| -> Result<BigUint, ProtocolError> {
                let mut total = BigUint::from(0u8);
                for p in std::iter::once(current).chain(
                    previous
                        .iter()
                        .filter(|p| cutoff.is_none_or(|c| p.accepted_at_ms > c)),
                ) {
                    for v in p.values.iter().filter(|v| v.asset == cap.asset) {
                        total += number(&v.amount)?;
                    }
                }
                Ok(total)
            };
            if sum(None)? > number(&cap.lifetime)? {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::LimitExceededValue,
                    "shared asset-unit lifetime budget exceeded",
                ));
            }
            for w in &cap.rolling_windows {
                if sum(Some(
                    current.accepted_at_ms.saturating_sub(w.duration_ms.get()),
                ))? > number(&w.maximum)?
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::LimitExceededValue,
                        "shared asset-unit rolling budget exceeded",
                    ));
                }
            }
        }
        for w in &self.limits.operation_rate_limits {
            let count = previous
                .iter()
                .filter(|p| {
                    p.accepted_at_ms > current.accepted_at_ms.saturating_sub(w.duration_ms.get())
                })
                .count() as u64;
            if count >= w.maximum.get() {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::SignerRateBackstopDenied,
                    "shared session operation rate exceeded",
                ));
            }
        }
        for w in &self.limits.signature_rate_limits {
            let count = previous
                .iter()
                .filter(|p| {
                    p.accepted_at_ms > current.accepted_at_ms.saturating_sub(w.duration_ms.get())
                })
                .try_fold(current.signature_count, |n, p| {
                    n.checked_add(p.signature_count)
                });
            if count.is_none_or(|n| n > w.maximum.get()) {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::SignerRateBackstopDenied,
                    "shared session signature rate exceeded",
                ));
            }
        }
        Ok(())
    }
}

impl SessionAccounting {
    pub fn canonical_values(
        values: &[SessionAssetAmount],
    ) -> Result<Vec<SessionAssetAmount>, ProtocolError> {
        use num_bigint::BigUint;
        use std::{collections::BTreeMap, str::FromStr};
        let mut totals = BTreeMap::<(String, String), BigUint>::new();
        for v in values {
            *totals
                .entry((v.asset.chain.as_str().to_owned(), v.asset.asset.clone()))
                .or_default() += BigUint::from_str(v.amount.as_str())
                .map_err(|_| invalid("invalid session asset quantity"))?;
        }
        totals
            .into_iter()
            .map(|((chain, asset), n)| {
                Ok(SessionAssetAmount {
                    asset: AssetId {
                        chain: Token::new(chain)?,
                        asset,
                    },
                    amount: DecimalU256::parse(n.to_string())
                        .map_err(|_| invalid("session asset quantity overflow"))?,
                })
            })
            .collect()
    }
}

impl SessionAccounting {
    pub fn from_petal_claim(
        claim: &crate::PetalUseClaim,
        budget: Option<&SessionBudget>,
    ) -> Result<Self, ProtocolError> {
        let mut values: Vec<_> = claim
            .declared_debits
            .iter()
            .map(|d| SessionAssetAmount {
                asset: d.asset.clone(),
                amount: d.amount.clone(),
            })
            .collect();
        if let crate::DeclaredFee::Fee {
            chain,
            asset,
            amount,
        } = &claim.declared_fee
        {
            values.push(SessionAssetAmount {
                asset: AssetId {
                    chain: chain.clone(),
                    asset: asset.clone(),
                },
                amount: amount.clone(),
            });
        }
        Ok(Self {
            system_use: None,
            values: Self::canonical_values(&values)?,
            budget_id: budget.map(SessionBudget::budget_id).transpose()?,
        })
    }
}

impl SystemSessionScope {
    pub fn validate_use(&self, use_: &SystemSessionUse) -> Result<(), ProtocolError> {
        use num_bigint::BigUint;
        use std::str::FromStr;
        self.validate()?;
        if !self.actions.contains(&use_.action)
            || !self.chains.contains(&use_.chain)
            || !self.destinations.iter().any(|d| {
                &d.chain == use_.chain.chain()
                    && match use_.chain {
                        SystemSessionChain::Evm { .. } => {
                            d.destination.eq_ignore_ascii_case(&use_.recipient)
                        }
                        SystemSessionChain::Solana { .. } => d.destination == use_.recipient,
                    }
            })
            || match (&use_.action, &use_.token) {
                (SystemSessionAction::NativeTransfer, None) => false,
                (SystemSessionAction::Erc20Transfer, Some(token)) => {
                    !self.tokens.contains(token)
                        || !matches!(use_.chain, SystemSessionChain::Evm { .. })
                }
                _ => true,
            }
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "transfer is outside the immutable session scope",
            ));
        }
        let accounting = use_.accounting(None)?;
        for v in accounting.values {
            let cap = self
                .per_action_value_limits
                .iter()
                .find(|c| c.asset == v.asset)
                .ok_or_else(|| invalid("session asset has no per-action limit"))?;
            if BigUint::from_str(v.amount.as_str())
                .map_err(|_| invalid("invalid session quantity"))?
                > BigUint::from_str(cap.maximum.as_str())
                    .map_err(|_| invalid("invalid session ceiling"))?
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::LimitExceededValue,
                    "typed session per-action ceiling exceeded",
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionWindowState {
    pub asset: AssetId,
    pub duration_ms: DecimalU64,
    pub maximum: DecimalU256,
    pub used: DecimalU256,
    pub remaining: DecimalU256,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudgetState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_state: Option<crate::SessionPoolState>,
    pub budget_id: Digest32,
    pub observed_at_ms: DecimalU64,
    pub operations: DecimalU64,
    pub signatures: DecimalU64,
    pub rolling_windows: Vec<SessionWindowState>,
    pub asset_usage: Vec<SessionAssetAmount>,
    /// Totals include outstanding reservations and ambiguous outcomes.
    pub includes_reserved_and_quarantined: bool,
}
impl SessionBudget {
    pub fn usage_state(
        &self,
        previous: &[SessionRecordedUse],
        now: u64,
    ) -> Result<SessionBudgetState, ProtocolError> {
        use num_bigint::BigUint;
        use std::str::FromStr;
        let n = |v: &DecimalU256| {
            BigUint::from_str(v.as_str()).map_err(|_| invalid("invalid session quantity"))
        };
        let decimal = |v: BigUint| {
            DecimalU256::parse(v.to_string()).map_err(|_| invalid("session usage overflow"))
        };
        let mut signatures = 0u64;
        let mut values = Vec::new();
        for p in previous {
            signatures = signatures
                .checked_add(p.signature_count)
                .ok_or_else(|| invalid("session signature usage overflow"))?;
            values.extend_from_slice(&p.values);
        }
        let remaining = |maximum: BigUint, used: &BigUint| {
            if maximum > *used {
                maximum - used
            } else {
                BigUint::from(0u8)
            }
        };
        let mut windows = Vec::new();
        for cap in &self.limits.value_limits {
            for w in &cap.rolling_windows {
                let mut used = BigUint::from(0u8);
                for p in previous.iter().filter(|p| {
                    p.accepted_at_ms <= now
                        && p.accepted_at_ms > now.saturating_sub(w.duration_ms.get())
                }) {
                    for value in p.values.iter().filter(|v| v.asset == cap.asset) {
                        used += n(&value.amount)?;
                    }
                }
                windows.push(SessionWindowState {
                    asset: cap.asset.clone(),
                    duration_ms: w.duration_ms.clone(),
                    maximum: w.maximum.clone(),
                    remaining: decimal(remaining(n(&w.maximum)?, &used))?,
                    used: decimal(used)?,
                });
            }
        }
        Ok(SessionBudgetState {
            pool_state: None,
            budget_id: self.budget_id()?,
            observed_at_ms: DecimalU64::new(now),
            operations: DecimalU64::new(previous.len() as u64),
            signatures: DecimalU64::new(signatures),
            rolling_windows: windows,
            asset_usage: SessionAccounting::canonical_values(&values)?,
            includes_reserved_and_quarantined: true,
        })
    }
}

impl SessionBudget {
    pub fn requires_trusted_time(&self) -> bool {
        !self.limits.operation_rate_limits.is_empty()
            || !self.limits.signature_rate_limits.is_empty()
            || self
                .limits
                .value_limits
                .iter()
                .any(|v| !v.rolling_windows.is_empty())
    }
}

#[cfg(test)]
#[test]
fn native_session_scope_refuses_unpriced_layer_two_fees_and_sol_freshness() {
    let mut scope = SystemSessionScope {
        component_id: Token::new("bloom-machine").unwrap(),
        actions: vec![SystemSessionAction::NativeTransfer],
        chains: vec![SystemSessionChain::Evm {
            chain: Token::new("evm-137").unwrap(),
            chain_id: DecimalU64::new(137),
        }],
        destinations: vec![PolicyDestination {
            chain: Token::new("evm-137").unwrap(),
            destination: "0x1111111111111111111111111111111111111111".into(),
        }],
        tokens: vec![],
        per_action_value_limits: vec![SessionValueCeiling {
            asset: AssetId {
                chain: Token::new("evm-137").unwrap(),
                asset: "native".into(),
            },
            maximum: DecimalU256::parse("100").unwrap(),
        }],
    };
    scope.validate().unwrap();
    for chain_id in [10, 8453] {
        scope.chains = vec![SystemSessionChain::Evm {
            chain: Token::new(format!("evm-{chain_id}")).unwrap(),
            chain_id: DecimalU64::new(chain_id),
        }];
        scope.destinations[0].chain = Token::new(format!("evm-{chain_id}")).unwrap();
        assert!(scope.validate().is_err());
    }
    scope.chains = vec![SystemSessionChain::Solana {
        chain: Token::new("solana").unwrap(),
        genesis_hash: "genesis".into(),
    }];
    assert!(scope.validate().is_err());
    scope.chains = vec![SystemSessionChain::Solana {
        chain: Token::new("solana-mainnet").unwrap(),
        genesis_hash: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d".into(),
    }];
    scope.destinations[0].chain = Token::new("solana-mainnet").unwrap();
    scope.per_action_value_limits[0].asset.chain = Token::new("solana-mainnet").unwrap();
    scope.validate().unwrap();
    scope.actions.push(SystemSessionAction::Erc20Transfer);
    assert!(scope.validate().is_err());
    scope.actions.pop();
    scope.tokens.push(AssetId {
        chain: Token::new("solana-mainnet").unwrap(),
        asset: "mint".into(),
    });
    assert!(scope.validate().is_err());
}

#[cfg(test)]
mod token_allowance_tests {
    use super::*;
    use crate::{KeySpec, ValueLimit, ValueWindow};
    fn n(v: &str) -> DecimalU256 {
        DecimalU256::parse(v).unwrap()
    }
    fn asset(name: &str) -> AssetId {
        AssetId {
            chain: Token::new("evm-137").unwrap(),
            asset: name.into(),
        }
    }
    fn budget() -> SessionBudget {
        SessionBudget {
            token_policy: None,
            wallet_id: Token::new("wallet").unwrap(),
            policy_version: DecimalU64::new(1),
            policy_digest: Digest32::from_bytes([1; 32]),
            wallet_revocation_epoch: DecimalU64::new(0),
            member_keys: vec![KeyRef {
                backend: Token::new("local").unwrap(),
                backend_instance: Token::new("test").unwrap(),
                locator: "key".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: Digest32::from_bytes([2; 32]),
                derivation: None,
            }],
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(u64::MAX),
                max_signatures: DecimalU64::new(u64::MAX),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: ["usdc", "pusd", "native"]
                    .into_iter()
                    .map(|s| ValueLimit {
                        asset: asset(s),
                        lifetime: n("1000000000"),
                        rolling_windows: vec![ValueWindow {
                            maximum: n("100"),
                            duration_ms: DecimalU64::new(100),
                        }],
                    })
                    .collect(),
            },
            per_action_value_limits: ["usdc", "pusd", "native"]
                .into_iter()
                .map(|s| SessionValueCeiling {
                    asset: asset(s),
                    maximum: n("70"),
                })
                .collect(),
            not_before_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(u64::MAX),
        }
    }
    fn use_(name: &str, amount: &str, time: u64) -> SessionRecordedUse {
        SessionRecordedUse {
            accepted_at_ms: time,
            signature_count: 1,
            values: vec![SessionAssetAmount {
                asset: asset(name),
                amount: n(amount),
            }],
        }
    }
    #[test]
    fn tokens_are_independent_and_reserved_spending_counts() {
        let b = budget();
        let first = use_("usdc", "60", 10);
        b.check_reservation(std::slice::from_ref(&first), &use_("pusd", "50", 11))
            .unwrap();
        assert!(
            b.check_reservation(&[first], &use_("usdc", "50", 11))
                .is_err()
        );
    }
    #[test]
    fn rolling_capacity_returns_at_exact_boundary_without_expiring_permission() {
        for duration in [100, 86_400_000, 604_800_000] {
            let mut b = budget();
            for cap in &mut b.limits.value_limits {
                cap.rolling_windows[0].duration_ms = DecimalU64::new(duration);
            }
            let id = b.budget_id().unwrap();
            let first = use_("usdc", "60", 10);
            assert!(
                b.check_reservation(
                    std::slice::from_ref(&first),
                    &use_("usdc", "50", 10 + duration - 1)
                )
                .is_err()
            );
            b.check_reservation(&[first], &use_("usdc", "50", 10 + duration))
                .unwrap();
            assert_eq!(id, b.budget_id().unwrap());
            assert_eq!(b.expires_at_ms.get(), u64::MAX);
        }
    }
    #[test]
    fn unknown_assets_and_wrong_chains_need_owner_review() {
        let b = budget();
        assert!(b.check_reservation(&[], &use_("unknown", "1", 10)).is_err());
        let mut wrong = use_("usdc", "1", 10);
        wrong.values[0].asset.chain = Token::new("evm-1").unwrap();
        assert!(b.check_reservation(&[], &wrong).is_err());
    }
    #[test]
    fn batches_and_fees_cannot_split_the_per_action_cap() {
        let b = budget();
        let mut current = use_("usdc", "40", 10);
        current.values.push(current.values[0].clone());
        assert!(b.check_reservation(&[], &current).is_err());
        let mut current = use_("native", "40", 10);
        current.values.push(SessionAssetAmount {
            asset: asset("native"),
            amount: n("31"),
        });
        assert!(b.check_reservation(&[], &current).is_err());
        assert!(SessionAccounting::canonical_values(&[SessionAssetAmount {asset:asset("usdc"),amount:n("115792089237316195423570985008687907853269984665640564039457584007913129639935")},SessionAssetAmount {asset:asset("usdc"),amount:n("1")}]).is_err());
    }
    #[test]
    fn identity_commits_accounts_tokens_limits_and_validity() {
        let b = budget();
        let id = b.budget_id().unwrap();
        let mut changed = b.clone();
        changed.member_keys[0].locator = "other".into();
        assert_ne!(id, changed.budget_id().unwrap());
        let mut changed = b.clone();
        changed.limits.value_limits[0].rolling_windows[0].maximum = n("99");
        assert_ne!(id, changed.budget_id().unwrap());
        let mut changed = b.clone();
        changed.per_action_value_limits[0].maximum = n("69");
        assert_ne!(id, changed.budget_id().unwrap());
    }
    #[test]
    fn status_has_per_token_remaining_capacity() {
        let b = budget();
        let uses = [use_("usdc", "60", 10), use_("pusd", "20", 11)];
        let state = b.usage_state(&uses, 12).unwrap();
        assert_eq!(
            state
                .rolling_windows
                .iter()
                .find(|w| w.asset == asset("usdc"))
                .unwrap()
                .remaining,
            n("40")
        );
        assert_eq!(
            state
                .rolling_windows
                .iter()
                .find(|w| w.asset == asset("pusd"))
                .unwrap()
                .remaining,
            n("80")
        );
        assert_eq!(
            b.usage_state(&uses, 110)
                .unwrap()
                .rolling_windows
                .iter()
                .find(|w| w.asset == asset("usdc"))
                .unwrap()
                .remaining,
            n("100")
        );
    }
    #[test]
    fn old_usd_grants_are_rejected_instead_of_silently_converted() {
        let mut old = serde_json::to_value(budget()).unwrap();
        old["usd_policy"] = serde_json::json!({"schema_version":2});
        assert!(serde_json::from_value::<SessionBudget>(old).is_err());
    }
}
