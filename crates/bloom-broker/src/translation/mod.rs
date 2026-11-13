//! Explicit nominal translations at the Broker's north/south API boundary.

/// Translates a fieldless enum between `north` and `south` variant for
/// variant, as functions named `$to_signer` (north to south) and
/// `$to_machine` (south to north); `_` skips a direction. Each generated
/// `match` names every variant of its source type, so a variant added to
/// either API without a counterpart fails to compile.
macro_rules! unit_enum_translation {
    ($ty:ident: $to_signer:tt, $to_machine:tt { $($variant:ident),+ $(,)? }) => {
        unit_enum_translation!(@fn $to_signer, north, south, $ty, $($variant),+);
        unit_enum_translation!(@fn $to_machine, south, north, $ty, $($variant),+);
    };
    (@fn _, $from:ident, $to:ident, $ty:ident, $($variant:ident),+) => {};
    (@fn ($vis:vis $name:ident), $from:ident, $to:ident, $ty:ident, $($variant:ident),+) => {
        $vis fn $name(value: $from::$ty) -> $to::$ty {
            match value {
                $($from::$ty::$variant => $to::$ty::$variant,)+
            }
        }
    };
}

pub mod approval;
pub(crate) mod ceremony;
pub mod custody;
pub(crate) mod error;
pub mod key;
pub(crate) mod policy;
pub(crate) mod revocation;
pub(crate) mod service;
pub(crate) mod signing;
pub(crate) mod wallet_account;
