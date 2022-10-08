//! A simple implementation of the [TOTP](https://www.rfc-editor.org/rfc/rfc6238) and [HOTP](https://www.rfc-editor.org/rfc/rfc4226) algorithms.

pub mod rfc;
pub mod util;

pub use rfc::{hotp, totp};
pub use util::{check_hotp, check_totp};
