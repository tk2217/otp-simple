//! A simple implementation of the [TOTP](https://www.rfc-editor.org/rfc/rfc6238) and [HOTP](https://www.rfc-editor.org/rfc/rfc4226) algorithms.
//! 
//! *Note: Most functions in this crate will require a hash function to be specified via a type parameter.
//! It is recommended to specify [SHA-1](https://docs.rs/sha1/latest/sha1/type.Sha1.html) for maximum compatibility,
//! but many clients also support using [SHA-256](https://docs.rs/sha2/latest/sha2/type.Sha256.html) and [SHA-512](https://docs.rs/sha2/latest/sha2/type.Sha512.html).*

#![cfg_attr(not(test), no_std)]

pub mod rfc;
pub mod util;

pub use rfc::{hotp, totp};
pub use util::{check_hotp, check_totp};
