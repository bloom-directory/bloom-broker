//! Key and cryptographic identifier translations.

use bloom_broker_api as north;
use bloom_signer_api as south;

pub(crate) fn key_spec_to_signer(value: north::KeySpec) -> south::KeySpec {
    match value {
        north::KeySpec::Secp256k1 => south::KeySpec::Secp256k1,
        north::KeySpec::Ed25519 => south::KeySpec::Ed25519,
    }
}

pub(crate) fn key_spec_to_machine(value: south::KeySpec) -> north::KeySpec {
    match value {
        south::KeySpec::Secp256k1 => north::KeySpec::Secp256k1,
        south::KeySpec::Ed25519 => north::KeySpec::Ed25519,
    }
}

pub(crate) fn crypto_suite_to_signer(value: north::CryptoSuite) -> south::CryptoSuite {
    match value {
        north::CryptoSuite::Secp256k1Keccak256Recoverable => {
            south::CryptoSuite::Secp256k1Keccak256Recoverable
        }
        north::CryptoSuite::Secp256k1Sha256Recoverable => {
            south::CryptoSuite::Secp256k1Sha256Recoverable
        }
        north::CryptoSuite::Ed25519Message => south::CryptoSuite::Ed25519Message,
    }
}

pub(crate) fn crypto_suite_to_machine(value: south::CryptoSuite) -> north::CryptoSuite {
    match value {
        south::CryptoSuite::Secp256k1Keccak256Recoverable => {
            north::CryptoSuite::Secp256k1Keccak256Recoverable
        }
        south::CryptoSuite::Secp256k1Sha256Recoverable => {
            north::CryptoSuite::Secp256k1Sha256Recoverable
        }
        south::CryptoSuite::Ed25519Message => north::CryptoSuite::Ed25519Message,
    }
}

pub(crate) fn derivation_profile_to_signer(
    value: north::DerivationProfile,
) -> south::DerivationProfile {
    match value {
        north::DerivationProfile::Bip44EvmSecp256k1V1 => {
            south::DerivationProfile::Bip44EvmSecp256k1V1
        }
        north::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
            south::DerivationProfile::Bip44SolanaSlip10Ed25519V1
        }
    }
}

pub(crate) fn derivation_profile_to_machine(
    value: south::DerivationProfile,
) -> north::DerivationProfile {
    match value {
        south::DerivationProfile::Bip44EvmSecp256k1V1 => {
            north::DerivationProfile::Bip44EvmSecp256k1V1
        }
        south::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
            north::DerivationProfile::Bip44SolanaSlip10Ed25519V1
        }
    }
}

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

pub(crate) fn key_ref_to_signer(value: north::KeyRef) -> south::KeyRef {
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
