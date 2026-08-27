//! Layered Broker configuration for non-secret operational limits.
//!
//! Precedence is compiled defaults, then the protected JSON configuration
//! file, then `BLOOM_BROKER`-prefixed environment overrides.
//!
//! Only the non-secret `ceremony_limits` object is merged this way. The rest
//! of the configuration file carries signing seeds, so it keeps its direct,
//! zeroized decode path: no seed is ever copied into the layered
//! configuration, and no environment variable can introduce or replace key
//! material.

use std::collections::HashMap;

use bloom_broker_api::{ProtocolError, ProtocolErrorCode};
use config::{Config, Environment, File, FileFormat};

use crate::ceremony::CeremonyLimits;

/// Environment prefix and nested-key separator, so
/// `ceremony_limits.creation_window_ms` is overridden by
/// `BLOOM_BROKER_CEREMONY_LIMITS__CREATION_WINDOW_MS`.
pub const ENVIRONMENT_PREFIX: &str = "BLOOM_BROKER";
pub const ENVIRONMENT_SEPARATOR: &str = "__";

const CEREMONY_LIMITS_KEY: &str = "ceremony_limits";

/// Merge and validate the global ceremony admission limits.
///
/// `document` is the `ceremony_limits` object as it appeared in the protected
/// configuration file, if the deployment supplied one.
pub fn ceremony_limits(
    document: Option<&serde_json::Value>,
) -> Result<CeremonyLimits, ProtocolError> {
    merge_ceremony_limits(document, None)
}

fn merge_ceremony_limits(
    document: Option<&serde_json::Value>,
    environment: Option<HashMap<String, String>>,
) -> Result<CeremonyLimits, ProtocolError> {
    let defaults = CeremonyLimits::default();
    let mut builder = Config::builder()
        .set_default(
            "ceremony_limits.maximum_concurrent_sessions",
            defaults.maximum_concurrent_sessions as u64,
        )
        .and_then(|builder| {
            builder.set_default(
                "ceremony_limits.creation_window_ms",
                defaults.creation_window_ms,
            )
        })
        .and_then(|builder| {
            builder.set_default(
                "ceremony_limits.maximum_creations_per_wallet",
                defaults.maximum_creations_per_wallet as u64,
            )
        })
        .and_then(|builder| {
            builder.set_default(
                "ceremony_limits.maximum_anonymous_registrations",
                defaults.maximum_anonymous_registrations as u64,
            )
        })
        .map_err(invalid)?;
    if let Some(document) = document {
        let nested = serde_json::json!({ CEREMONY_LIMITS_KEY: document }).to_string();
        builder = builder.add_source(File::from_str(&nested, FileFormat::Json));
    }
    let mut overrides = Environment::with_prefix(ENVIRONMENT_PREFIX)
        // The prefix is separated by a single underscore so existing
        // BLOOM_BROKER_* variables keep their spelling, while nested keys use
        // the doubled separator.
        .prefix_separator("_")
        .separator(ENVIRONMENT_SEPARATOR)
        .ignore_empty(true)
        .try_parsing(true);
    if let Some(environment) = environment {
        overrides = overrides.source(Some(environment.into_iter().collect()));
    }
    builder
        .add_source(overrides)
        .build()
        .map_err(invalid)?
        .get::<CeremonyLimits>(CEREMONY_LIMITS_KEY)
        .map_err(invalid)?
        .validated()
}

fn invalid(error: config::ConfigError) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        format!(
            "Broker ceremony_limits configuration is invalid: {error}; correct the ceremony_limits object in the Broker configuration file or its {ENVIRONMENT_PREFIX}_CEREMONY_LIMITS{ENVIRONMENT_SEPARATOR}* environment overrides"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::{
        DEFAULT_CREATION_WINDOW_MS, DEFAULT_MAXIMUM_ANONYMOUS_REGISTRATIONS,
        DEFAULT_MAXIMUM_CONCURRENT_SESSIONS, DEFAULT_MAXIMUM_CREATIONS_PER_WALLET,
    };

    /// The environment layer is exercised through an injected map rather than
    /// the process environment: it is the same source `config` reads real
    /// variables into, and tests stay independent of one another.
    fn environment(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn compiled_defaults_apply_when_nothing_is_configured() {
        let limits = ceremony_limits(None).unwrap();
        assert_eq!(limits, CeremonyLimits::default());
        assert_eq!(
            limits.maximum_concurrent_sessions,
            DEFAULT_MAXIMUM_CONCURRENT_SESSIONS
        );
        assert_eq!(limits.maximum_concurrent_sessions, 16);
        assert_eq!(limits.creation_window_ms, DEFAULT_CREATION_WINDOW_MS);
        assert_eq!(limits.creation_window_ms, 300_000);
        assert_eq!(
            limits.maximum_creations_per_wallet,
            DEFAULT_MAXIMUM_CREATIONS_PER_WALLET
        );
        assert_eq!(limits.maximum_creations_per_wallet, 12);
        assert_eq!(
            limits.maximum_anonymous_registrations,
            DEFAULT_MAXIMUM_ANONYMOUS_REGISTRATIONS
        );
        assert_eq!(limits.maximum_anonymous_registrations, 4);
    }

    #[test]
    fn configuration_file_values_override_compiled_defaults_field_by_field() {
        let document = serde_json::json!({
            "maximum_creations_per_wallet": 3,
            "creation_window_ms": 60_000,
        });
        let limits = merge_ceremony_limits(Some(&document), Some(environment(&[]))).unwrap();
        assert_eq!(limits.maximum_creations_per_wallet, 3);
        assert_eq!(limits.creation_window_ms, 60_000);
        // Unmentioned fields keep the compiled defaults.
        assert_eq!(limits.maximum_concurrent_sessions, 16);
        assert_eq!(limits.maximum_anonymous_registrations, 4);
    }

    #[test]
    fn environment_overrides_take_precedence_over_the_file() {
        let document = serde_json::json!({
            "maximum_creations_per_wallet": 3,
            "maximum_anonymous_registrations": 2,
        });
        let limits = merge_ceremony_limits(
            Some(&document),
            Some(environment(&[
                (
                    "BLOOM_BROKER_CEREMONY_LIMITS__MAXIMUM_CREATIONS_PER_WALLET",
                    "7",
                ),
                ("BLOOM_BROKER_CEREMONY_LIMITS__CREATION_WINDOW_MS", "90000"),
                // An unrelated Broker variable must not disturb the merge.
                ("BLOOM_BROKER_CONFIG", "/etc/bloom/broker.json"),
            ])),
        )
        .unwrap();
        assert_eq!(limits.maximum_creations_per_wallet, 7);
        assert_eq!(limits.creation_window_ms, 90_000);
        assert_eq!(limits.maximum_anonymous_registrations, 2);
        assert_eq!(limits.maximum_concurrent_sessions, 16);
    }

    #[test]
    fn zero_and_out_of_range_values_are_rejected_with_actionable_errors() {
        for (field, value) in [
            ("maximum_concurrent_sessions", 0),
            ("maximum_creations_per_wallet", 0),
            ("maximum_anonymous_registrations", 0),
            ("creation_window_ms", 0),
            ("maximum_concurrent_sessions", 1_025),
            ("creation_window_ms", 86_400_001),
        ] {
            let document = serde_json::json!({ field: value });
            let error = merge_ceremony_limits(Some(&document), Some(environment(&[])))
                .expect_err("out-of-range ceremony limit must not start Broker");
            assert_eq!(error.code, ProtocolErrorCode::MalformedFrame);
            assert!(
                error.message.contains(field)
                    && error.message.contains("BLOOM_BROKER_CEREMONY_LIMITS__"),
                "error must name the field and its override: {}",
                error.message
            );
        }
    }

    #[test]
    fn unknown_and_unparsable_settings_fail_closed() {
        let unknown = serde_json::json!({ "maximum_creations_per_kind": 3 });
        assert!(merge_ceremony_limits(Some(&unknown), Some(environment(&[]))).is_err());

        for value in ["not-a-number", "-1"] {
            let error = merge_ceremony_limits(
                None,
                Some(environment(&[(
                    "BLOOM_BROKER_CEREMONY_LIMITS__MAXIMUM_CREATIONS_PER_WALLET",
                    value,
                )])),
            )
            .expect_err("unusable environment override must not start Broker");
            assert_eq!(error.code, ProtocolErrorCode::MalformedFrame);
            assert!(error.message.contains("ceremony_limits"));
        }
    }

    #[test]
    fn effective_summary_reports_only_the_four_non_secret_values() {
        let summary = CeremonyLimits::default().effective_summary();
        assert_eq!(
            summary,
            "maximum_concurrent_sessions=16 creation_window_ms=300000 \
             maximum_creations_per_wallet=12 maximum_anonymous_registrations=4"
        );
    }
}
