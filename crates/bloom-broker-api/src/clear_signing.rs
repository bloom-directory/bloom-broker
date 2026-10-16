//! The wallet-policy extension that turns clear signing on.
//!
//! Clear signing is authority, not display: it makes Broker refuse contract
//! calls it cannot read, and it carries the two refusals the owner can lift.
//! So it lives in the canonical policy document and changes only through the
//! existing policy ceremony. What Broker can read is compiled into Broker.
//!
//! The extension is optional. Omitting it preserves the previous
//! serialization exactly and leaves the wallet on the existing envelope
//! review, which is not advertised as clear signing.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSigningPolicy {
    /// Whether this wallet may approve exact payloads Bloom cannot explain.
    pub opaque_exact_allowed: bool,
    /// Whether a maximum-U256 allowance may be requested at all. Enabling it
    /// still requires a separate exact approval for each allowance.
    pub unlimited_allowance_allowed: bool,
}
