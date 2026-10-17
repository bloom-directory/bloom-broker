//! Public card requests. Checkout facts and recipient keys have no Machine RPC.
use crate::{OperationId, Token};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TravelerPublic {
    pub traveler_id: Token,
    pub label: String,
    pub fields: Vec<TravelerField>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TravelerField {
    GivenName,
    FamilyName,
    BornOn,
    Gender,
    Nationality,
    Email,
    Phone,
    DocumentKind,
    DocumentNumber,
    DocumentCountry,
    DocumentExpiry,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TravelerSaveRequest {
    pub operation_id: OperationId,
    pub traveler_id: Token,
    pub label: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TravelerDeleteRequest {
    pub operation_id: OperationId,
    pub traveler_id: Token,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardPublic {
    pub card_id: Token,
    pub label: String,
    pub brand: String,
    pub last4: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardAddRequest {
    pub operation_id: OperationId,
    pub card_id: Token,
    pub label: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardDeleteRequest {
    pub operation_id: OperationId,
    pub card_id: Token,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CardOperationState {
    Prepared,
    Consumed,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
    Missing,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardOperationStatus {
    pub operation_id: OperationId,
    pub state: CardOperationState,
}
