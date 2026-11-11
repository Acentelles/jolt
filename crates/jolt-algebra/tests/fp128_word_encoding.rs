#![cfg(feature = "solinas")]
#![expect(clippy::unwrap_used, reason = "tests construct canonical fixtures")]

use jolt_algebra::solinas::Prime128Offset6A23801F as Field;
use jolt_algebra::CanonicalEncoding;

const MODULUS: u128 = u128::MAX - (0x6a23_801f - 1);

#[test]
fn word_canonical_tuple_boundaries_and_consumption() {
    let config = bincode::config::standard();
    for value in [0, 1, (1u128 << 64) - 1, 1u128 << 64, MODULUS - 1] {
        let mut input = value.to_le_bytes().to_vec();
        input.extend_from_slice(&[0xaa, 0xbb]);
        let (field, consumed): (Field, usize) =
            bincode::serde::decode_from_slice(&input, config).unwrap();
        assert_eq!(field.to_u128_checked(), Some(value));
        assert_eq!(consumed, 16);
        assert_eq!(
            bincode::serde::encode_to_vec(field, config).unwrap(),
            value.to_le_bytes()
        );
    }
    for value in [MODULUS, MODULUS + 1, u128::MAX] {
        assert!(
            bincode::serde::decode_from_slice::<Field, _>(&value.to_le_bytes(), config).is_err()
        );
    }
}

#[test]
fn word_truncated_and_single_bit_tuples() {
    let config = bincode::config::standard();
    let input = [0u8; 16];
    for length in 0..16 {
        assert!(bincode::serde::decode_from_slice::<Field, _>(&input[..length], config).is_err());
    }
    // Every bit below the modulus is canonical, including the limb boundary.
    for bit in 0..128 {
        let value = 1u128 << bit;
        let (field, consumed): (Field, usize) =
            bincode::serde::decode_from_slice(&value.to_le_bytes(), config).unwrap();
        assert_eq!((field.to_u128_checked(), consumed), (Some(value), 16));
    }
}
