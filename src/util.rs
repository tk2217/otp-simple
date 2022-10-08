//! Additional utilities for working with TOTP and HOTP.

use crate::{hotp, totp};
use hmac::digest::{
    block_buffer::Eager,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero, U256},
    HashMarker,
};

/// Checks the validity of a TOTP code with a specific amount of skew as specified in [RFC6238](https://www.rfc-editor.org/rfc/rfc6238#section-6).
pub fn check_totp<D>(
    time: u64,
    step: u64,
    secret: &[u8],
    digits: u32,
    skew: (u64, u64),
    expected: u32,
) -> bool
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    iter_skew(time, step, skew)
        .map(|e| totp::<D>(e, step, secret, digits))
        .any(|code| code == expected)
}

/// Checks the validity of an HOTP code with a specific amount of skew as specified in [RFC4266](https://www.rfc-editor.org/rfc/rfc4226#section-7.4).
pub fn check_hotp<D>(time: u64, secret: &[u8], digits: u32, skew: u64, expected: u32) -> bool
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    iter_skew(time, 1, (0, skew))
        .map(|e| hotp::<D>(e, secret, digits))
        .any(|code| code == expected)
}

fn iter_skew(time: u64, step: u64, skew: (u64, u64)) -> impl Iterator<Item = u64> {
    let start = time - (step * skew.0);
    let end = time + (step * skew.1);

    (start..=end).step_by(step as usize)
}

#[cfg(test)]
mod test {
    use crate::util::iter_skew;

    #[test]
    fn test_iter_skew() {
        let values = [
            (
                (10000, 2, (2, 4)),
                vec![9996, 9998, 10000, 10002, 10004, 10006, 10008],
            ),
            ((100, 1, (0, 5)), vec![100, 101, 102, 103, 104, 105]),
        ];

        for ((time, step, skew), output) in values {
            assert_eq!(iter_skew(time, step, skew).collect::<Vec<_>>(), output);
        }
    }
}
