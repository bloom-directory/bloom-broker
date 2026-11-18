//! The authority a policy update grants or withdraws, as the owner reviews it.
//!
//! Broker derives this diff from the current and proposed policies, binds its
//! digest into the `PolicyUpdateReviewManifest` the owner approves, and the
//! Signer's commit receipt carries that digest. Machine computes the same
//! digest before asking, and Broker refuses a request whose digest differs, so
//! both sides call this one function rather than keeping copies that can
//! drift apart.
//!
//! Destinations are diffed by decoded identity, the same `(chain,
//! comparable)` value [`crate::address`] matches claims by. A destination is
//! added only when no spelling of its account was allowed before, and removed
//! only when no spelling of it is allowed after. Changing only how an allowed
//! account is written, such as replacing an EIP-55 checksummed address with its
//! lowercase form or dropping one of two spellings of one account, grants and
//! withdraws nothing, so it is reported apart from authority changes in
//! `respelled_destinations`.
//!
//! Every spelling that differs between the two policies still appears
//! somewhere in the diff: under an added or removed destination, or in a
//! respelling. The owner is never asked to approve new policy bytes without
//! being shown what changed in them.

use crate::{
    CanonicalWalletPolicy, DecimalU64, Digest32, LegacyClearSigningPolicy, ProtocolError,
    ProtocolErrorCode, Token, address,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// v1 set-diffed destinations as exact `(chain, destination)` strings. v2
/// diffs them by decoded identity and adds `respelled_destinations`, so a v1
/// digest and a v2 digest of the same update can never be mistaken for each
/// other.
pub const POLICY_AUTHORITY_DIFF_DOMAIN: &[u8] = b"bloom-policy-authority-diff/v2";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityDiff {
    pub maximum_approval_lifetime_ms_before: DecimalU64,
    pub maximum_approval_lifetime_ms_after: DecimalU64,
    pub added_petal_packages: Vec<Digest32>,
    pub removed_petal_packages: Vec<Digest32>,
    /// Accounts no spelling of which was allowed before.
    pub added_destinations: Vec<PolicyAuthorityDestination>,
    /// Accounts no spelling of which is allowed after.
    pub removed_destinations: Vec<PolicyAuthorityDestination>,
    /// Accounts allowed before and after whose spellings changed. Not an
    /// authority change.
    pub respelled_destinations: Vec<PolicyAuthorityRespelling>,
    pub added_required_verifiers: Vec<PolicyAuthorityVerifier>,
    pub removed_required_verifiers: Vec<PolicyAuthorityVerifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_legacy_clear_signing: Option<LegacyClearSigningPolicy>,
}

/// One account added to or removed from `allowed_destinations`.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityDestination {
    pub chain: Token,
    /// The account's first spelling in byte order, on the side that lists it.
    pub destination: String,
    /// Its other spellings on that side, when the policy lists it more than
    /// once. They name the same account and add no authority of their own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_spelled: Vec<String>,
}

/// One account allowed before and after, written differently.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityRespelling {
    pub chain: Token,
    /// Every spelling of the account in the current policy, in byte order.
    pub before: Vec<String>,
    /// Every spelling of the account in the proposed policy, in byte order.
    pub after: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityVerifier {
    pub verifier_id: Token,
    pub verifier_digest: Digest32,
}

impl PolicyAuthorityDiff {
    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_AUTHORITY_DIFF_DOMAIN);
        hasher.update(serde_jcs::to_vec(self).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("policy canonicalization failed: {error}"),
            )
        })?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}

/// The authority `proposed` grants or withdraws relative to `current`.
pub fn canonical_policy_authority_diff(
    current: &CanonicalWalletPolicy,
    proposed: &CanonicalWalletPolicy,
) -> PolicyAuthorityDiff {
    let (added_petal_packages, removed_petal_packages) = set_diff(
        current.allowed_petal_packages.iter().cloned(),
        proposed.allowed_petal_packages.iter().cloned(),
    );
    let (added_required_verifiers, removed_required_verifiers) = set_diff(
        current.required_verifiers.iter().map(verifier),
        proposed.required_verifiers.iter().map(verifier),
    );
    let before = spellings_by_account(current);
    let after = spellings_by_account(proposed);
    let mut added_destinations = Vec::new();
    let mut respelled_destinations = Vec::new();
    for (account, spellings) in &after {
        let chain = &account.0;
        match before.get(account) {
            None => added_destinations.push(destination(chain, spellings)),
            Some(previous) if previous != spellings => {
                respelled_destinations.push(PolicyAuthorityRespelling {
                    chain: chain.clone(),
                    before: previous.iter().cloned().collect(),
                    after: spellings.iter().cloned().collect(),
                })
            }
            Some(_) => {}
        }
    }
    let mut removed_destinations = before
        .iter()
        .filter(|(key, _)| !after.contains_key(*key))
        .map(|((chain, _), spellings)| destination(chain, spellings))
        .collect::<Vec<_>>();
    // Grouped by decoded account, so the order above follows `Comparable`
    // rather than anything the owner reads. Sort by what is shown.
    added_destinations.sort();
    removed_destinations.sort();
    respelled_destinations.sort();

    PolicyAuthorityDiff {
        maximum_approval_lifetime_ms_before: DecimalU64::new(current.maximum_approval_lifetime_ms),
        maximum_approval_lifetime_ms_after: DecimalU64::new(proposed.maximum_approval_lifetime_ms),
        added_petal_packages,
        removed_petal_packages,
        added_destinations,
        removed_destinations,
        respelled_destinations,
        added_required_verifiers,
        removed_required_verifiers,
        removed_legacy_clear_signing: (current.clear_signing != proposed.clear_signing)
            .then(|| current.clear_signing.clone())
            .flatten(),
    }
}

type Account = (Token, address::Comparable);

/// Each account a policy allows, with every spelling the policy uses for it.
/// An entry this build cannot decode is its own account, keyed by its exact
/// spelling, as it is when claims are matched.
fn spellings_by_account(policy: &CanonicalWalletPolicy) -> BTreeMap<Account, BTreeSet<String>> {
    let mut accounts = BTreeMap::<Account, BTreeSet<String>>::new();
    for entry in &policy.allowed_destinations {
        accounts
            .entry((
                entry.chain.clone(),
                address::comparable(&entry.chain, &entry.destination),
            ))
            .or_default()
            .insert(entry.destination.clone());
    }
    accounts
}

fn destination(chain: &Token, spellings: &BTreeSet<String>) -> PolicyAuthorityDestination {
    let mut spellings = spellings.iter().cloned();
    PolicyAuthorityDestination {
        chain: chain.clone(),
        destination: spellings
            .next()
            .expect("an account is only recorded with a spelling"),
        also_spelled: spellings.collect(),
    }
}

fn verifier(value: &crate::RequiredVerifier) -> PolicyAuthorityVerifier {
    PolicyAuthorityVerifier {
        verifier_id: value.verifier_id.clone(),
        verifier_digest: value.verifier_digest.clone(),
    }
}

fn set_diff<T: Ord + Clone>(
    before: impl IntoIterator<Item = T>,
    after: impl IntoIterator<Item = T>,
) -> (Vec<T>, Vec<T>) {
    let before = before.into_iter().collect::<BTreeSet<_>>();
    let after = after.into_iter().collect::<BTreeSet<_>>();
    (
        after.difference(&before).cloned().collect(),
        before.difference(&after).cloned().collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PolicyDestination, RequiredVerifier};

    const CHECKSUMMED: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    const LOWERCASE: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

    fn token(value: &str) -> Token {
        Token::new(value).expect("valid token")
    }

    fn policy(destinations: &[(&str, &str)]) -> CanonicalWalletPolicy {
        CanonicalWalletPolicy {
            wallet_id: token("wallet"),
            maximum_approval_lifetime_ms: 600_000,
            allowed_petal_packages: Vec::new(),
            allowed_destinations: destinations
                .iter()
                .map(|(chain, destination)| PolicyDestination {
                    chain: token(chain),
                    destination: (*destination).to_owned(),
                })
                .collect(),
            required_verifiers: Vec::new(),
            clear_signing: None,
        }
    }

    fn named(chain: &str, destination: &str, also: &[&str]) -> PolicyAuthorityDestination {
        PolicyAuthorityDestination {
            chain: token(chain),
            destination: destination.to_owned(),
            also_spelled: also.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn respelled(chain: &str, before: &[&str], after: &[&str]) -> PolicyAuthorityRespelling {
        PolicyAuthorityRespelling {
            chain: token(chain),
            before: before.iter().map(|value| (*value).to_owned()).collect(),
            after: after.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn diff(
        current: &[(&str, &str)],
        proposed: &[(&str, &str)],
    ) -> (
        Vec<PolicyAuthorityDestination>,
        Vec<PolicyAuthorityDestination>,
        Vec<PolicyAuthorityRespelling>,
    ) {
        let diff = canonical_policy_authority_diff(&policy(current), &policy(proposed));
        (
            diff.added_destinations,
            diff.removed_destinations,
            diff.respelled_destinations,
        )
    }

    /// pm#88's first case. Replacing an EIP-55 address with its lowercase form
    /// used to show the owner one destination added and one removed.
    #[test]
    fn a_respelling_grants_and_withdraws_nothing() {
        let (added, removed, respellings) = diff(&[("base", CHECKSUMMED)], &[("base", LOWERCASE)]);
        assert!(added.is_empty(), "{added:?}");
        assert!(removed.is_empty(), "{removed:?}");
        assert_eq!(
            respellings,
            vec![respelled("base", &[CHECKSUMMED], &[LOWERCASE])]
        );
    }

    /// pm#88's second case. With one account listed in two spellings, dropping
    /// one used to show a removal while the other still allowed the account.
    #[test]
    fn dropping_one_of_two_spellings_removes_nothing() {
        let (added, removed, respellings) = diff(
            &[("base", CHECKSUMMED), ("base", LOWERCASE)],
            &[("base", LOWERCASE)],
        );
        assert!(added.is_empty(), "{added:?}");
        assert!(removed.is_empty(), "{removed:?}");
        assert_eq!(
            respellings,
            vec![respelled("base", &[CHECKSUMMED, LOWERCASE], &[LOWERCASE])]
        );
    }

    #[test]
    fn dropping_every_spelling_removes_the_account_once() {
        let (added, removed, respellings) =
            diff(&[("base", CHECKSUMMED), ("base", LOWERCASE)], &[]);
        assert!(added.is_empty(), "{added:?}");
        assert_eq!(removed, vec![named("base", CHECKSUMMED, &[LOWERCASE])]);
        assert!(respellings.is_empty(), "{respellings:?}");
    }

    #[test]
    fn an_account_added_in_two_spellings_is_added_once() {
        let (added, removed, respellings) =
            diff(&[], &[("base", LOWERCASE), ("base", CHECKSUMMED)]);
        assert_eq!(added, vec![named("base", CHECKSUMMED, &[LOWERCASE])]);
        assert!(removed.is_empty(), "{removed:?}");
        assert!(respellings.is_empty(), "{respellings:?}");
    }

    #[test]
    fn reordering_or_repeating_a_spelling_is_no_change() {
        let current = [("base", LOWERCASE), ("polygon", CHECKSUMMED)];
        let proposed = [
            ("polygon", CHECKSUMMED),
            ("base", LOWERCASE),
            ("base", LOWERCASE),
        ];
        assert_eq!(diff(&current, &proposed), (vec![], vec![], vec![]));
    }

    /// A destination entry only matches its own chain, so moving an address
    /// to another chain is a real change in authority.
    #[test]
    fn the_same_address_on_another_chain_is_another_account() {
        let (added, removed, respellings) =
            diff(&[("base", CHECKSUMMED)], &[("polygon", LOWERCASE)]);
        assert_eq!(added, vec![named("polygon", LOWERCASE, &[])]);
        assert_eq!(removed, vec![named("base", CHECKSUMMED, &[])]);
        assert!(respellings.is_empty(), "{respellings:?}");
    }

    /// Nothing here may fold together two spellings the claim matcher keeps
    /// apart: a Petal class, an address on a chain this build cannot decode,
    /// and base58, where case is data.
    #[test]
    fn spellings_claims_keep_apart_stay_apart() {
        for (chain, before, after) in [
            ("base", "petal:Swap", "petal:swap"),
            ("localnet", CHECKSUMMED, LOWERCASE),
            (
                "solana",
                "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",
                "cktruq2mttgrgkxjtyksdkhjudc2c4tgdzyb98oezy8",
            ),
        ] {
            let (added, removed, respellings) = diff(&[(chain, before)], &[(chain, after)]);
            assert_eq!(added, vec![named(chain, after, &[])], "{chain}");
            assert_eq!(removed, vec![named(chain, before, &[])], "{chain}");
            assert!(respellings.is_empty(), "{chain}: {respellings:?}");
        }
    }

    /// bech32 case is spelling, but the HRP and the Bitcoin script are part of
    /// the account, as they are when claims are matched.
    #[test]
    fn bech32_case_is_spelling_and_prefix_and_script_are_identity() {
        let account = "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c";
        let upper = "COSMOS1W508D6QEJXTDG4Y5R3ZARVARY0C5XW7K6AH60C";
        let operator = "cosmosvaloper1w508d6qejxtdg4y5r3zarvary0c5xw7klfr0rt";
        assert_eq!(
            diff(&[("cosmos", account)], &[("cosmos", upper)]),
            (
                vec![],
                vec![],
                vec![respelled("cosmos", &[account], &[upper])]
            )
        );
        let (added, removed, _) = diff(&[("cosmos", account)], &[("cosmos", operator)]);
        assert_eq!(added, vec![named("cosmos", operator, &[])]);
        assert_eq!(removed, vec![named("cosmos", account, &[])]);

        let p2pkh = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        let p2wpkh = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let p2wpkh_upper = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let (added, removed, _) = diff(&[("bitcoin", p2pkh)], &[("bitcoin", p2wpkh)]);
        assert_eq!(added, vec![named("bitcoin", p2wpkh, &[])]);
        assert_eq!(removed, vec![named("bitcoin", p2pkh, &[])]);
        assert_eq!(
            diff(&[("bitcoin", p2wpkh)], &[("bitcoin", p2wpkh_upper)]),
            (
                vec![],
                vec![],
                vec![respelled("bitcoin", &[p2wpkh], &[p2wpkh_upper])]
            )
        );
    }

    /// The owner approves new policy bytes, so no destination spelling may
    /// change without appearing in the diff, whichever list it lands in.
    #[test]
    fn every_changed_spelling_appears_in_the_diff() {
        let current = [
            ("base", CHECKSUMMED),
            ("base", LOWERCASE),
            ("polygon", LOWERCASE),
            ("cosmos", "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c"),
            ("base", "petal:swap"),
            ("localnet", "0xrecipient"),
        ];
        let proposed = [
            ("base", LOWERCASE),
            ("polygon", CHECKSUMMED),
            ("polygon", LOWERCASE),
            ("cosmos", "COSMOS1W508D6QEJXTDG4Y5R3ZARVARY0C5XW7K6AH60C"),
            ("arbitrum", CHECKSUMMED),
            ("arbitrum", LOWERCASE),
            ("localnet", "0xRecipient"),
        ];
        let diff = canonical_policy_authority_diff(&policy(&current), &policy(&proposed));
        let mut reported = BTreeSet::new();
        for entry in diff
            .added_destinations
            .iter()
            .chain(&diff.removed_destinations)
        {
            reported.insert((entry.chain.to_string(), entry.destination.clone()));
            for other in &entry.also_spelled {
                reported.insert((entry.chain.to_string(), other.clone()));
            }
        }
        for entry in &diff.respelled_destinations {
            for spelling in entry.before.iter().chain(&entry.after) {
                reported.insert((entry.chain.to_string(), spelling.clone()));
            }
        }
        let side = |entries: &[(&str, &str)]| {
            entries
                .iter()
                .map(|(chain, destination)| ((*chain).to_owned(), (*destination).to_owned()))
                .collect::<BTreeSet<_>>()
        };
        let (before, after) = (side(&current), side(&proposed));
        for changed in before.symmetric_difference(&after) {
            assert!(reported.contains(changed), "{changed:?} is not reported");
        }
        assert_eq!(
            diff.added_destinations,
            vec![
                named("arbitrum", CHECKSUMMED, &[LOWERCASE]),
                named("localnet", "0xRecipient", &[]),
            ]
        );
        assert_eq!(
            diff.removed_destinations,
            vec![
                named("base", "petal:swap", &[]),
                named("localnet", "0xrecipient", &[]),
            ]
        );
    }

    /// Pins the v2 encoding and digest. Machine asserts the same vector, so a
    /// change here that is not made on both sides fails a test in each.
    #[test]
    fn digest_matches_reviewed_v2_vector() {
        let mut current = policy(&[
            ("base", CHECKSUMMED),
            ("base", LOWERCASE),
            ("ethereum", "old"),
        ]);
        current.maximum_approval_lifetime_ms = 10;
        current.allowed_petal_packages = vec![Digest32::from_bytes([1; 32])];
        current.required_verifiers = vec![RequiredVerifier {
            verifier_id: token("human"),
            verifier_digest: Digest32::from_bytes([3; 32]),
        }];
        let mut proposed = policy(&[("base", LOWERCASE), ("ethereum", "new")]);
        proposed.maximum_approval_lifetime_ms = 20;
        proposed.allowed_petal_packages = vec![Digest32::from_bytes([4; 32])];
        let diff = canonical_policy_authority_diff(&current, &proposed);
        assert_eq!(
            String::from_utf8(serde_jcs::to_vec(&diff).unwrap()).unwrap(),
            V2_VECTOR_JCS
        );
        assert_eq!(diff.digest().unwrap().as_str(), V2_VECTOR_DIGEST);
    }

    const V2_VECTOR_JCS: &str = concat!(
        r#"{"added_destinations":[{"chain":"ethereum","destination":"new"}],"#,
        r#""added_petal_packages":["0404040404040404040404040404040404040404040404040404040404040404"],"#,
        r#""added_required_verifiers":[],"#,
        r#""maximum_approval_lifetime_ms_after":"20","#,
        r#""maximum_approval_lifetime_ms_before":"10","#,
        r#""removed_destinations":[{"chain":"ethereum","destination":"old"}],"#,
        r#""removed_petal_packages":["0101010101010101010101010101010101010101010101010101010101010101"],"#,
        r#""removed_required_verifiers":[{"verifier_digest":"#,
        r#""0303030303030303030303030303030303030303030303030303030303030303","verifier_id":"human"}],"#,
        r#""respelled_destinations":[{"after":["0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"],"#,
        r#""before":["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","#,
        r#""0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"],"chain":"base"}]}"#,
    );
    const V2_VECTOR_DIGEST: &str =
        "44f12ff959f3988f53c160d105d1bbb7e6395ee739fe49be59dd9f2da3d717e6";
}
