//! Opaque identifiers for Broker-owned Petal authority sent to Signer.

use bloom_broker_api::{Digest32, ProtocolError, ProtocolErrorCode, Token};
use sha2::{Digest as _, Sha256};

const PETAL_LINEAGE_AUTHORITY_DOMAIN: &[u8] = b"bloom-petal-lineage-authority/v1\0";
const PETAL_ROUTE_RESOURCE_DOMAIN: &[u8] = b"bloom-petal-route-resource/v1\0";

pub(crate) fn authority_id(lineage_id: &str) -> Result<Digest32, ProtocolError> {
    bloom_broker_api::validate_lineage_id(lineage_id)?;
    Ok(domain_digest(PETAL_LINEAGE_AUTHORITY_DOMAIN, lineage_id))
}

pub(crate) fn resource_id(route_id: &str) -> Result<Digest32, ProtocolError> {
    if route_id.is_empty() {
        return Err(ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            "Petal route ID cannot be empty",
        ));
    }
    Ok(domain_digest(PETAL_ROUTE_RESOURCE_DOMAIN, route_id))
}

pub(crate) fn delegate_id(agent_id: Option<&str>) -> Result<Token, ProtocolError> {
    Ok(Token::new(agent_id.unwrap_or("unscoped-petal").to_owned())?)
}

fn domain_digest(domain: &[u8], value: &str) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value.as_bytes());
    Digest32::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn petal_identifiers_are_opaque_domain_separated_and_stable() {
        let lineage = format!("pln1_{}", "a".repeat(52));
        assert_eq!(
            authority_id(&lineage).unwrap().as_str(),
            "ab2c63a3b19373480f98ae25ba7dbb6689b9f7da5785fe46c029128e767397f0"
        );
        assert_eq!(
            resource_id("r000001").unwrap().as_str(),
            "ce36bd3f9625a744e4782c339fff4374ea81ba1b18bf4428dafe58446b481bae"
        );
        assert_ne!(
            authority_id(&lineage).unwrap(),
            resource_id(&lineage).unwrap()
        );
        assert_eq!(delegate_id(Some("desk-a")).unwrap().as_str(), "desk-a");
        assert_eq!(delegate_id(None).unwrap().as_str(), "unscoped-petal");
    }
}
