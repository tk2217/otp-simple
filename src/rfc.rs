use hmac::{
    digest::{
        block_buffer::Eager,
        core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
        crypto_common::BlockSizeUser,
        typenum::{IsLess, Le, NonZero, U256},
        HashMarker,
    },
    Hmac, Mac,
};

pub const DEFAULT_STEP: u64 = 30;
pub const DEFAULT_DIGITS: u8 = 6;

#[inline]
pub fn totp<D>(time: u64, step: u64, digits: u32, secret: &[u8]) -> u32
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
    truncate_code(totp_raw::<D>(time, step, secret), digits)
}

#[inline]
pub fn totp_raw<D>(time: u64, step: u64, secret: &[u8]) -> u32
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
    dbg!(time / step);
    hotp_raw::<D>(time / step, secret)
}

#[inline]
pub fn hotp<D>(count: u64, digits: u32, secret: &[u8]) -> u32
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
    truncate_code(hotp_raw::<D>(count, secret), digits)
}

pub fn hotp_raw<D>(count: u64, secret: &[u8]) -> u32
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
    let mut mac = Hmac::<D>::new_from_slice(secret).expect("HMAC can take key of any size");

    mac.update(&count.to_be_bytes());

    let signature = &mac.finalize().into_bytes()[..];

    twist_bytes(signature)
}

fn truncate_code(code: u32, digits: u32) -> u32 {
    code % (10u32.pow(digits))
}

fn twist_bytes(input: &[u8]) -> u32 {
    assert!(input.len() >= 16, "input length must be at least 16");

    let offset = input.last().unwrap() & 0xf;
    let offset = offset as usize;

    let binary = &input[offset..=offset + 3];
    let binary = u32::from_be_bytes([binary[0], binary[1], binary[2], binary[3]]);
    let binary = binary & 0x7fffffff;

    binary
}

#[cfg(test)]
mod test {
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};

    use super::*;

    #[test]
    fn test_hotp() {
        const DIGITS: u32 = 6;

        let secret = "12345678901234567890".as_bytes();

        let values = [
            (0x4c93cf18, 755224),
            (0x41397eea, 287082),
            (0x082fef30, 359152),
            (0x66ef7655, 969429),
            (0x61c5938a, 338314),
            (0x33c083d4, 254676),
            (0x7256c032, 287922),
            (0x04e5b397, 162583),
            (0x2823443f, 399871),
            (0x2679dc69, 520489),
        ];

        for (i, value) in values.into_iter().enumerate() {
            assert_eq!(hotp_raw::<Sha1>(i as u64, secret), value.0);
            assert_eq!(hotp::<Sha1>(i as u64, DIGITS, secret), value.1);
        }
    }

    #[test]
    fn test_totp() {
        const STEP: u64 = DEFAULT_STEP;
        const DIGITS: u32 = 8;
        
        let secrets = (b"12345678901234567890", b"12345678901234567890123456789012", b"1234567890123456789012345678901234567890123456789012345678901234");

        let values = [
            (59, (94287082, 46119246, 90693936)),
            (1111111109, (07081804, 68084774, 25091201)),
            (1111111111, (14050471, 67062674, 99943326)),
            (1234567890, (89005924, 91819424, 93441116)),
            (2000000000, (69279037, 90698825, 38618901)),
            (20000000000u64, (65353130, 77737706, 47863826)),
        ];

        for (time, codes) in values {
            assert_eq!(totp::<Sha1>(time, STEP, DIGITS, secrets.0), codes.0);
            assert_eq!(totp::<Sha256>(time, STEP, DIGITS, secrets.1), codes.1);
            assert_eq!(totp::<Sha512>(time, STEP, DIGITS, secrets.2), codes.2);
        }
    }
}
