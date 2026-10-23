//! The known ERC-20 tokens, compiled into both Broker and Machine.
//!
//! Broker shows a listed token's name and human amount; Machine resolves a
//! symbol such as `USDC` to its address and lists the tokens it knows. One
//! list serves both, so they cannot disagree. `tokens/tokens.py` rebuilds it
//! before each release from curated lists, checked on chain.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

/// One row of `tokens/tokens.json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KnownToken {
    pub chain_id: u64,
    /// Lowercase `0x`-prefixed address.
    pub address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    /// A proxy whose implementation its admin can replace.
    #[serde(default)]
    pub upgradeable: bool,
}

static TOKENS: LazyLock<Vec<KnownToken>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../tokens/tokens.json"))
        .expect("tokens.json is checked by this crate's tests")
});

pub fn known_tokens() -> &'static [KnownToken] {
    &TOKENS
}

pub fn tokens_on(chain_id: u64) -> impl Iterator<Item = &'static KnownToken> {
    known_tokens()
        .iter()
        .filter(move |token| token.chain_id == chain_id)
}

/// The one token on `chain_id` with this symbol, ignoring case. `None` when
/// none is listed or when two are, so a symbol never picks between tokens.
pub fn token_by_symbol(chain_id: u64, symbol: &str) -> Option<&'static KnownToken> {
    let mut matches = tokens_on(chain_id).filter(|token| token.symbol.eq_ignore_ascii_case(symbol));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_parses_and_resolves_majors_by_symbol() {
        assert!(known_tokens().len() > 1000);
        let usdc = token_by_symbol(8453, "usdc").unwrap();
        assert_eq!(usdc.address, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
        assert_eq!(usdc.decimals, 6);
        // Two listed tokens share this symbol on Ethereum: no guess.
        assert!(token_by_symbol(1, "LIT").is_none());
        assert!(token_by_symbol(1, "NOT-A-TOKEN").is_none());
    }
}
