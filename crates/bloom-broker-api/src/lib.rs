//! Broker-owned public Machine-to-Broker service contract.

mod approval;
mod ceremony;
mod claims;
mod codec;
mod crypto;
mod error;
mod methods;
mod petal_key;
mod policy;
mod provenance;
mod revocation;
mod service;
mod signing;
mod wallet_account;

pub use approval::*;
pub use ceremony::*;
pub use claims::*;
pub use codec::*;
pub use crypto::*;
pub use error::*;
pub use methods::*;
pub use petal_key::*;
pub use policy::*;
pub use provenance::*;
pub use revocation::*;
pub use service::*;
pub use signing::*;
pub use wallet_account::*;

pub use bloom_rpc_wire::{
    AuthenticatedPeer, Base64UrlBytes, BootEpoch, DecimalU64, DecimalU256, Digest32, EnvelopeKind,
    FRAME_MAX_BYTES, HelloChallenge, JSON_MAX_DEPTH, JSON_MAX_LIST_LENGTH, JSON_MAX_STRING_BYTES,
    JournalHeadPolicy, OperationId, ProtocolVersion, ProtocolVersionRange, RPC_ENVELOPE_SCHEMA_V1,
    RequestNonce, SignedEnvelope, SignedJournalHead, Token, TypedRequestMethod, UnsignedEnvelope,
    WireError, WireErrorCode, decode_frame, encode_frame,
};

pub const BROKER_API_MAJOR: u16 = 1;
pub const BROKER_API_MINOR_MIN: u16 = 3;
pub const BROKER_API_MINOR_MAX: u16 = 4;
pub const BROKER_API_CURRENT: ProtocolVersion =
    ProtocolVersion::new(BROKER_API_MAJOR, BROKER_API_MINOR_MAX);
pub const BROKER_API_RANGE: ProtocolVersionRange =
    ProtocolVersionRange::new(BROKER_API_MAJOR, BROKER_API_MINOR_MIN, BROKER_API_MINOR_MAX);

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn broker_api_range_accepts_only_the_current_v1_3() {
        assert!(BROKER_API_RANGE.contains(BROKER_API_CURRENT));
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
}
