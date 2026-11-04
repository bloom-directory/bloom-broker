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
    GaslessEip3009V1,
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
    pub fn capability_schema(&self) -> String {
        format!("bloom.reusable-profile/{}", self.id)
    }
    pub fn is_advertised(&self, schemas: &[Token]) -> bool {
        schemas
            .iter()
            .any(|s| s.as_str() == self.capability_schema())
    }

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
    static PROFILES: [ReusableSigningProfile; 2] = [
        ReusableSigningProfile {
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
        },
        ReusableSigningProfile {
            id: "gasless.relay.eip3009.v1",
            display_name: "Gasless Relay USDC payments",
            operation_class: "gasless.relay",
            effects_schema: 1,
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            assets: &[
                ReusableProfileAsset {
                    network: "evm-1",
                    asset: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                },
                ReusableProfileAsset {
                    network: "evm-8453",
                    asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                },
                ReusableProfileAsset {
                    network: "evm-10",
                    asset: "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
                },
                ReusableProfileAsset {
                    network: "evm-137",
                    asset: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
                },
                ReusableProfileAsset {
                    network: "evm-43114",
                    asset: "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",
                },
            ],
            verifier: ReusableEffectsVerifier::GaslessEip3009V1,
        },
    ];
    &PROFILES
}

/// Choose only the claim's exact operation class, never the first profile of
/// another class declared by the same package.
pub fn reusable_signing_profile_for_class(class: &str) -> Option<&'static ReusableSigningProfile> {
    reusable_signing_profiles()
        .iter()
        .find(|profile| profile.operation_class == class)
}

/// The supported message profiles still require their existing independent
/// verifier at every signing use. Other review classes keep exact approval.
pub fn reusable_message_session_class(terms: &crate::SealedApprovalTerms, class: &str) -> bool {
    terms.session_budget.as_ref().is_some_and(|budget| {
        reusable_signing_profile_for_class(class).is_some()
            && (class == "polymarket.order.poly1271" || budget.token_policy.is_some())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_are_selected_only_by_exact_operation_class() {
        assert_eq!(
            reusable_signing_profile_for_class("gasless.relay")
                .unwrap()
                .verifier,
            ReusableEffectsVerifier::GaslessEip3009V1
        );
        assert_eq!(
            reusable_signing_profile_for_class("polymarket.order.poly1271")
                .unwrap()
                .verifier,
            ReusableEffectsVerifier::PolymarketBuyV1
        );
        for class in [
            "gasless",
            "gasless.relay.other",
            "venice-x402.topup",
            "unknown",
        ] {
            assert!(reusable_signing_profile_for_class(class).is_none());
        }
    }
    #[test]
    fn only_supported_fee_free_certified_profiles_are_discoverable() {
        for profile in reusable_signing_profiles() {
            assert!(!profile.is_advertised(&[]));
            assert!(profile.is_advertised(&[Token::new(profile.capability_schema()).unwrap()]));
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
}
