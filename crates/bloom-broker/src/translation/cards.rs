//! Public card and traveler projections across the nominal API boundary.
use bloom_broker_api as north;
use bloom_signer_api as south;

pub(crate) fn traveler(value: south::TravelerPublic) -> north::TravelerPublic {
    north::TravelerPublic {
        traveler_id: value.traveler_id,
        label: value.label,
        fields: value.fields.into_iter().map(field).collect(),
    }
}

fn field(value: south::TravelerField) -> north::TravelerField {
    match value {
        south::TravelerField::GivenName => north::TravelerField::GivenName,
        south::TravelerField::FamilyName => north::TravelerField::FamilyName,
        south::TravelerField::BornOn => north::TravelerField::BornOn,
        south::TravelerField::Gender => north::TravelerField::Gender,
        south::TravelerField::Nationality => north::TravelerField::Nationality,
        south::TravelerField::Email => north::TravelerField::Email,
        south::TravelerField::Phone => north::TravelerField::Phone,
        south::TravelerField::DocumentKind => north::TravelerField::DocumentKind,
        south::TravelerField::DocumentNumber => north::TravelerField::DocumentNumber,
        south::TravelerField::DocumentCountry => north::TravelerField::DocumentCountry,
        south::TravelerField::DocumentExpiry => north::TravelerField::DocumentExpiry,
    }
}

pub(crate) fn card(value: south::CardPublic) -> north::CardPublic {
    north::CardPublic {
        card_id: value.card_id,
        label: value.label,
        brand: value.brand,
        last4: value.last4,
    }
}

pub(crate) fn status(value: south::CardOperationStatus) -> north::CardOperationStatus {
    north::CardOperationStatus {
        operation_id: value.operation_id,
        state: match value.state {
            south::CardOperationState::Prepared => north::CardOperationState::Prepared,
            south::CardOperationState::Consumed => north::CardOperationState::Consumed,
            south::CardOperationState::Succeeded => north::CardOperationState::Succeeded,
            south::CardOperationState::Failed => north::CardOperationState::Failed,
            south::CardOperationState::Cancelled => north::CardOperationState::Cancelled,
            south::CardOperationState::Expired => north::CardOperationState::Expired,
            south::CardOperationState::Missing => north::CardOperationState::Missing,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projections_preserve_every_wire_field() {
        let traveler = south::TravelerPublic {
            traveler_id: south::Token::new("test").unwrap(),
            label: "Test".into(),
            fields: vec![
                south::TravelerField::GivenName,
                south::TravelerField::FamilyName,
                south::TravelerField::BornOn,
                south::TravelerField::Gender,
                south::TravelerField::Nationality,
                south::TravelerField::Email,
                south::TravelerField::Phone,
                south::TravelerField::DocumentKind,
                south::TravelerField::DocumentNumber,
                south::TravelerField::DocumentCountry,
                south::TravelerField::DocumentExpiry,
            ],
        };
        assert_eq!(
            serde_json::to_value(super::traveler(traveler.clone())).unwrap(),
            serde_json::to_value(traveler).unwrap()
        );
        let card = south::CardPublic {
            card_id: south::Token::new("test").unwrap(),
            label: "Test".into(),
            brand: "Visa".into(),
            last4: "4242".into(),
        };
        assert_eq!(
            serde_json::to_value(super::card(card.clone())).unwrap(),
            serde_json::to_value(card).unwrap()
        );
        for state in [
            south::CardOperationState::Prepared,
            south::CardOperationState::Consumed,
            south::CardOperationState::Succeeded,
            south::CardOperationState::Failed,
            south::CardOperationState::Cancelled,
            south::CardOperationState::Expired,
            south::CardOperationState::Missing,
        ] {
            let status = south::CardOperationStatus {
                operation_id: south::OperationId::from_bytes([1; 32]),
                state,
            };
            assert_eq!(
                serde_json::to_value(super::status(status.clone())).unwrap(),
                serde_json::to_value(status).unwrap()
            );
        }
    }
}
