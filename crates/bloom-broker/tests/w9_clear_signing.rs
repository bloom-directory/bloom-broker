//! Clear signing at the authority boundary: the downgrade floor, and the
//! exact policy-diff bytes Machine also computes.

use bloom_broker::{
    authority::{AssuranceRegistry, BrokerAuthority, CanonicalWalletPolicy},
    journal::{AuditSigner, BrokerJournal},
};
use bloom_broker_api::{
    Base64UrlBytes, ClearSigningPolicy, DecimalU64, Digest32, SignedPolicySnapshot, Token,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc};

const POLICY_DOMAIN: &[u8] = b"bloom-policy-snapshot/v1";

struct TestAuditSigner;
impl AuditSigner for TestAuditSigner {
    fn key_id(&self) -> Token {
        token("audit-key")
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(&Sha256::digest(message)))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id == &self.key_id() && signature.decode() == Sha256::digest(message).as_slice() {
            Ok(())
        } else {
            Err("audit signature mismatch".into())
        }
    }
}

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}

struct Harness {
    authority: BrokerAuthority,
    policy_key: SigningKey,
    wallet: Token,
}

impl Harness {
    fn open(directory: Option<&std::path::Path>) -> Self {
        let policy_key = SigningKey::from_bytes(&[1; 32]);
        let journal = Arc::new(match directory {
            None => BrokerJournal::open_in_memory(Arc::new(TestAuditSigner)).unwrap(),
            Some(directory) => {
                BrokerJournal::open(directory.join("journal.sqlite"), Arc::new(TestAuditSigner))
                    .unwrap()
            }
        });
        let installer = SigningKey::from_bytes(&[2; 32]);
        let wallet = token("wallet-1");
        let mut policy_keys = BTreeMap::new();
        policy_keys.insert(
            wallet.as_str().to_owned(),
            (token("policy-key"), policy_key.verifying_key()),
        );
        let build = move |path: Option<std::path::PathBuf>| match path {
            None => BrokerAuthority::open_in_memory(
                journal.clone(),
                policy_keys,
                token("installer-key"),
                installer.verifying_key(),
                token("ceremony-key"),
                SigningKey::from_bytes(&[3; 32]).verifying_key(),
                token("revocation-key"),
                SigningKey::from_bytes(&[4; 32]).verifying_key(),
                AssuranceRegistry::compiled(vec![]).unwrap(),
            ),
            Some(path) => BrokerAuthority::open(
                path,
                journal.clone(),
                policy_keys,
                token("installer-key"),
                installer.verifying_key(),
                token("ceremony-key"),
                SigningKey::from_bytes(&[3; 32]).verifying_key(),
                token("revocation-key"),
                SigningKey::from_bytes(&[4; 32]).verifying_key(),
                AssuranceRegistry::compiled(vec![]).unwrap(),
            ),
        };
        Self {
            authority: build(directory.map(|directory| directory.join("authority.sqlite")))
                .unwrap(),
            policy_key,
            wallet,
        }
    }

    fn install_policy(&self, version: u64, clear_signing: Option<ClearSigningPolicy>) {
        let policy = CanonicalWalletPolicy {
            wallet_id: self.wallet.clone(),
            maximum_approval_lifetime_ms: 100_000,
            allowed_petal_packages: Vec::new(),
            allowed_destinations: Vec::new(),
            required_verifiers: Vec::new(),
            clear_signing,
        };
        self.authority
            .install_policy(&self.sign_policy(version, &policy))
            .unwrap();
    }

    fn sign_policy(&self, version: u64, policy: &CanonicalWalletPolicy) -> SignedPolicySnapshot {
        let canonical = serde_jcs::to_vec(policy).unwrap();
        let mut snapshot = SignedPolicySnapshot {
            wallet_id: self.wallet.clone(),
            version: DecimalU64::new(version),
            canonical_policy: Base64UrlBytes::from_bytes(&canonical),
            policy_digest: Digest32::from_bytes(Sha256::digest(&canonical).into()),
            policy_signing_key_id: token("policy-key"),
            policy_verifying_key: Base64UrlBytes::from_bytes(
                &self.policy_key.verifying_key().to_bytes(),
            ),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        let mut unsigned = snapshot.clone();
        unsigned.signer_signature = Base64UrlBytes::from_bytes(&[]);
        let mut message = POLICY_DOMAIN.to_vec();
        message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
        snapshot.signer_signature =
            Base64UrlBytes::from_bytes(&self.policy_key.sign(&message).to_bytes());
        snapshot
    }
}

fn clear_signing_policy() -> ClearSigningPolicy {
    ClearSigningPolicy::default()
}

#[test]
fn enabling_clear_signing_raises_the_downgrade_floor_before_the_policy_is_visible() {
    let directory = tempfile::tempdir().unwrap();
    {
        let harness = Harness::open(Some(directory.path()));
        harness.install_policy(1, None);
        assert_eq!(state_floor(directory.path()), None);
        harness.install_policy(2, Some(clear_signing_policy()));
        assert_eq!(state_floor(directory.path()), Some(2));
    }
    // Reopening with a build that understands the floor succeeds.
    drop(Harness::open(Some(directory.path())));

    // A build whose durable-state version is below the recorded floor refuses
    // to open the store at all, before it can mutate anything.
    raise_floor_beyond_this_build(directory.path());
    let journal = Arc::new(
        BrokerJournal::open(
            directory.path().join("journal.sqlite"),
            Arc::new(TestAuditSigner),
        )
        .unwrap(),
    );
    let error = BrokerAuthority::open(
        directory.path().join("authority.sqlite"),
        journal,
        BTreeMap::new(),
        token("installer-key"),
        SigningKey::from_bytes(&[2; 32]).verifying_key(),
        token("ceremony-key"),
        SigningKey::from_bytes(&[3; 32]).verifying_key(),
        token("revocation-key"),
        SigningKey::from_bytes(&[4; 32]).verifying_key(),
        AssuranceRegistry::compiled(vec![]).unwrap(),
    )
    .err()
    .expect("a store above this build's state version must not open")
    .to_string();
    assert!(error.contains("durable state version"), "{error}");
    assert!(error.contains("instead of downgrading"), "{error}");
}

fn state_floor(directory: &Path) -> Option<i64> {
    let connection = rusqlite::Connection::open(directory.join("journal.sqlite")).unwrap();
    connection
        .query_row(
            "SELECT minimum_state_version FROM store_compatibility WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .ok()
}

fn raise_floor_beyond_this_build(directory: &Path) {
    let connection = rusqlite::Connection::open(directory.join("journal.sqlite")).unwrap();
    connection
        .execute(
            "INSERT INTO store_compatibility(id, minimum_state_version) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET minimum_state_version = excluded.minimum_state_version",
            [bloom_broker::authority::BROKER_STATE_VERSION + 1],
        )
        .unwrap();
}

const UNLIMITED_ALLOWANCE_DIFF_JCS: &str = concat!(
    r#"{"added_destinations":[],"added_petal_packages":[],"added_required_verifiers":[],"#,
    r#""clear_signing":{"after":{"opaque_exact_allowed":false,"unlimited_allowance_allowed":true},"#,
    r#""before":{"opaque_exact_allowed":false,"unlimited_allowance_allowed":false}},"#,
    r#""maximum_approval_lifetime_ms_after":"100000","maximum_approval_lifetime_ms_before":"100000","#,
    r#""removed_destinations":[],"removed_petal_packages":[],"removed_required_verifiers":[]}"#,
);

#[test]
fn enabling_unlimited_allowances_is_a_visible_authority_change() {
    let mut before = clear_signing_policy();
    before.unlimited_allowance_allowed = false;
    let mut after = before.clone();
    after.unlimited_allowance_allowed = true;

    let unchanged = bloom_broker::authority::canonical_policy_authority_diff(
        &wallet_policy(Some(before.clone())),
        &wallet_policy(Some(before.clone())),
    );
    assert!(
        unchanged.clear_signing.is_none(),
        "an unchanged policy must not claim a clear-signing change"
    );

    let changed = bloom_broker::authority::canonical_policy_authority_diff(
        &wallet_policy(Some(before)),
        &wallet_policy(Some(after)),
    );
    let change = changed
        .clear_signing
        .as_ref()
        .expect("enabling unlimited allowances is an authority change the owner must see");
    assert!(!change.before.as_ref().unwrap().unlimited_allowance_allowed);
    assert!(change.after.as_ref().unwrap().unlimited_allowance_allowed);

    assert_eq!(
        serde_jcs::to_string(&changed).unwrap(),
        UNLIMITED_ALLOWANCE_DIFF_JCS,
        "Bloom's machine client asserts these same bytes; a change here must be made on both sides"
    );
}

/// A policy update that never mentions clear signing produces the diff it
/// always produced, so the digest a released Machine computes still matches.
#[test]
fn a_policy_update_without_clear_signing_keeps_its_exact_diff_bytes() {
    let diff = bloom_broker::authority::canonical_policy_authority_diff(
        &wallet_policy(None),
        &wallet_policy(None),
    );
    assert_eq!(
        serde_jcs::to_string(&diff).unwrap(),
        concat!(
            r#"{"added_destinations":[],"added_petal_packages":[],"added_required_verifiers":[],"#,
            r#""maximum_approval_lifetime_ms_after":"100000","#,
            r#""maximum_approval_lifetime_ms_before":"100000","#,
            r#""removed_destinations":[],"removed_petal_packages":[],"removed_required_verifiers":[]}"#,
        )
    );
}

fn wallet_policy(clear_signing: Option<ClearSigningPolicy>) -> CanonicalWalletPolicy {
    CanonicalWalletPolicy {
        wallet_id: token("wallet-1"),
        maximum_approval_lifetime_ms: 100_000,
        allowed_petal_packages: Vec::new(),
        allowed_destinations: Vec::new(),
        required_verifiers: Vec::new(),
        clear_signing,
    }
}
