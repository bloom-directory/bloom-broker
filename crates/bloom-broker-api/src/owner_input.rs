use serde::{Deserialize, Serialize};

use crate::{DecimalU64, OperationId};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerInputKind {
    EvmAddress,
}

/// Petal-supplied information rendered as context next to the input field.
/// It is display-only: it is not an approval or a claim about execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerInputDisplayContext {
    pub network: String,
    pub asset: String,
    pub amount_base_units: String,
    pub decimals: u8,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerInputRequest {
    pub operation_id: OperationId,
    pub kind: OwnerInputKind,
    pub context: OwnerInputDisplayContext,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerInputResponse {
    Pending {
        operation_id: OperationId,
        ceremony_url: String,
        expires_at_ms: DecimalU64,
    },
    Ready {
        operation_id: OperationId,
        value: String,
    },
}
