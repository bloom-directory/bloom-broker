//! Broker-owned public Machine-to-Broker service contract.

mod approval;
mod ceremony;
mod claims;
mod codec;
mod crypto;
mod error;
mod methods;
mod owner_input;
mod petal_key;
mod policy;
mod provenance;
mod revocation;
mod service;
mod signing;

pub use approval::*;
pub use ceremony::*;
pub use claims::*;
pub use codec::*;
pub use crypto::*;
pub use error::*;
pub use methods::*;
pub use owner_input::*;
pub use petal_key::*;
pub use policy::*;
pub use provenance::*;
pub use revocation::*;
pub use service::*;
pub use signing::*;

pub use bloom_rpc_wire::{
    AuthenticatedPeer, Base64UrlBytes, BootEpoch, DecimalU64, DecimalU256, Digest32, EnvelopeKind,
    FRAME_MAX_BYTES, HelloChallenge, JSON_MAX_DEPTH, JSON_MAX_LIST_LENGTH, JSON_MAX_STRING_BYTES,
    JournalHeadPolicy, OperationId, ProtocolVersion, ProtocolVersionRange, RPC_ENVELOPE_SCHEMA_V1,
    RequestNonce, SignedEnvelope, SignedJournalHead, Token, TypedRequestMethod, UnsignedEnvelope,
    WireError, WireErrorCode, decode_frame, encode_frame,
};

pub const BROKER_API_MAJOR: u16 = 1;
/// First minor whose decoders understand [`ProtocolError::rate_limit`].
///
/// Every decoder in this protocol is strict: an unknown field fails the frame
/// rather than being ignored. So the optional `rate_limit` object could not be
/// added under 1.3 — a 1.3 peer handed one would reject the whole error
/// instead of reading the retry hint inside it.
pub const RATE_LIMIT_DETAILS_MINOR: u16 = 4;
pub const OWNER_INPUT_MINOR: u16 = 5;
/// The negotiated range moves as a unit, so there is no accepted minor that
/// predates a field the Broker may emit. A 1.3 peer is refused at the hello,
/// before any response could carry `rate_limit`.
pub const BROKER_API_MINOR_MIN: u16 = OWNER_INPUT_MINOR;
pub const BROKER_API_MINOR_MAX: u16 = OWNER_INPUT_MINOR;
pub const BROKER_API_CURRENT: ProtocolVersion =
    ProtocolVersion::new(BROKER_API_MAJOR, BROKER_API_MINOR_MAX);
pub const BROKER_API_RANGE: ProtocolVersionRange =
    ProtocolVersionRange::new(BROKER_API_MAJOR, BROKER_API_MINOR_MIN, BROKER_API_MINOR_MAX);

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn broker_api_range_accepts_only_the_current_minor() {
        assert!(BROKER_API_RANGE.contains(BROKER_API_CURRENT));
        assert_eq!(BROKER_API_MINOR_MIN, BROKER_API_MINOR_MAX);
    }

    #[test]
    fn broker_api_range_rejects_incompatible_versions() {
        assert!(!BROKER_API_RANGE.contains(ProtocolVersion::new(
            BROKER_API_MAJOR + 1,
            BROKER_API_MINOR_MIN,
        )));
        assert!(!BROKER_API_RANGE.contains(ProtocolVersion::new(BROKER_API_MAJOR, 0,)));
        assert!(!BROKER_API_RANGE.contains(ProtocolVersion::new(
            BROKER_API_MAJOR,
            BROKER_API_MINOR_MAX + 1,
        )));
    }

    #[test]
    fn no_negotiable_minor_predates_the_rate_limit_field() {
        // The gate is the range itself: nothing below the minor that
        // introduced `rate_limit` can ever be negotiated, so no accepted peer
        // can be handed a field its decoder would refuse.
        const { assert!(BROKER_API_MINOR_MIN >= RATE_LIMIT_DETAILS_MINOR) };
        assert!(!BROKER_API_RANGE.contains(ProtocolVersion::new(
            BROKER_API_MAJOR,
            RATE_LIMIT_DETAILS_MINOR - 1,
        )));
    }
}
