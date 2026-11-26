//! Key and cryptographic identifier translations.

use bloom_broker_api as north;
use bloom_signer_api as south;

unit_enum_translation!(KeySpec: (pub(crate) key_spec_to_signer), (pub(crate) key_spec_to_machine) {
    Secp256k1,
    Ed25519,
});

unit_enum_translation!(CryptoSuite: (pub crypto_suite_to_signer), (pub(crate) crypto_suite_to_machine) {
    Secp256k1Keccak256Recoverable,
    Secp256k1Sha256Recoverable,
    Ed25519Message,
});

unit_enum_translation!(DerivationProfile: (pub(crate) derivation_profile_to_signer), (pub(crate) derivation_profile_to_machine) {
    Bip44EvmSecp256k1V1,
    Bip44SolanaSlip10Ed25519V1,
});

fn derivation_to_signer(value: north::DerivationRef) -> south::DerivationRef {
    match value {
        north::DerivationRef::Bip32Secp256k1 { root_key_id, path } => {
            south::DerivationRef::Bip32Secp256k1 { root_key_id, path }
        }
        north::DerivationRef::Bip39Multicurve {
            wallet_seed_ref,
            profile,
            path,
        } => south::DerivationRef::Bip39Multicurve {
            wallet_seed_ref,
            profile: derivation_profile_to_signer(profile),
            path,
        },
    }
}

fn derivation_to_machine(value: south::DerivationRef) -> north::DerivationRef {
    match value {
        south::DerivationRef::Bip32Secp256k1 { root_key_id, path } => {
            north::DerivationRef::Bip32Secp256k1 { root_key_id, path }
        }
        south::DerivationRef::Bip39Multicurve {
            wallet_seed_ref,
            profile,
            path,
        } => north::DerivationRef::Bip39Multicurve {
            wallet_seed_ref,
            profile: derivation_profile_to_machine(profile),
            path,
        },
    }
}

pub fn key_ref_to_signer(value: north::KeyRef) -> south::KeyRef {
    south::KeyRef {
        backend: value.backend,
        backend_instance: value.backend_instance,
        locator: value.locator,
        key_spec: key_spec_to_signer(value.key_spec),
        public_key_fingerprint: value.public_key_fingerprint,
        derivation: value.derivation.map(derivation_to_signer),
    }
}

pub(crate) fn key_ref_to_machine(value: south::KeyRef) -> north::KeyRef {
    north::KeyRef {
        backend: value.backend,
        backend_instance: value.backend_instance,
        locator: value.locator,
        key_spec: key_spec_to_machine(value.key_spec),
        public_key_fingerprint: value.public_key_fingerprint,
        derivation: value.derivation.map(derivation_to_machine),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_crypto_enums_are_exhaustive() {
        for suite in north::CryptoSuite::ALL {
            assert_eq!(
                crypto_suite_to_machine(crypto_suite_to_signer(suite)),
                suite
            );
        }
        for spec in [north::KeySpec::Secp256k1, north::KeySpec::Ed25519] {
            assert_eq!(key_spec_to_machine(key_spec_to_signer(spec)), spec);
        }
    }
}
