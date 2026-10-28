//! Broker-supported protocol adapters for automatic onboarding.
//!
//! A profile is eligibility metadata, never authority. Discovery additionally
//! requires the exact installed package, installer-signed route provenance,
//! wallet policy and owner-reviewed terms. Adding an effects declaration alone
//! does not add a protocol verifier or opt another Petal into automatic signing.
use crate::{AssetId, CryptoSuite, ProvenanceOperationClass, Token};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReusableEffectsVerifier {
    PolymarketBuyV1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReusableProfileAsset {
    pub network: &'static str,
    pub asset: &'static str,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableSigningProfile {
    pub id: &'static str,
    pub display_name: &'static str,
    pub operation_class: &'static str,
    pub effects_schema: u16,
    pub crypto_suite: CryptoSuite,
    pub assets: &'static [ReusableProfileAsset],
    pub verifier: ReusableEffectsVerifier,
}
impl ReusableSigningProfile {
    pub fn matches_certified_class(&self, class: &ProvenanceOperationClass) -> bool {
        class.operation_class.as_str() == self.operation_class
            && class.economic_effects_schema == Some(self.effects_schema)
            && class.fee_asset.is_none()
    }
    pub fn token_assets(&self) -> Vec<AssetId> {
        self.assets
            .iter()
            .map(|asset| AssetId {
                chain: Token::new(asset.network).expect("compiled profile network"),
                asset: asset.asset.into(),
            })
            .collect()
    }
}

pub fn reusable_signing_profiles() -> &'static [ReusableSigningProfile] {
    static PROFILES: [ReusableSigningProfile; 1] = [ReusableSigningProfile {
        id: "polymarket.buy.poly1271.v1",
        display_name: "Polymarket buys",
        operation_class: "polymarket.order.poly1271",
        effects_schema: 1,
        crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
        assets: &[ReusableProfileAsset {
            network: "evm-137",
            asset: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb",
        }],
        verifier: ReusableEffectsVerifier::PolymarketBuyV1,
    }];
    &PROFILES
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_supported_fee_free_certified_profiles_are_discoverable() {
        let profile = &reusable_signing_profiles()[0];
        let mut class = ProvenanceOperationClass {
            economic_effects_schema: Some(1),
            operation_class: Token::new(profile.operation_class).unwrap(),
            fee_asset: None,
        };
        assert!(profile.matches_certified_class(&class));
        class.economic_effects_schema = None;
        assert!(!profile.matches_certified_class(&class));
        class.economic_effects_schema = Some(2);
        assert!(!profile.matches_certified_class(&class));
        class.economic_effects_schema = Some(1);
        class.operation_class = Token::new("example.arbitrary-call").unwrap();
        assert!(!profile.matches_certified_class(&class));
        class.operation_class = Token::new(profile.operation_class).unwrap();
        class.fee_asset = Some(crate::ProvenanceFeeAsset {
            chain: Token::new("evm-137").unwrap(),
            asset: "native".into(),
        });
        assert!(!profile.matches_certified_class(&class));
        for asset in profile.token_assets() {
            assert!(crate::approved_session_asset(&asset).is_some());
        }
    }
}
