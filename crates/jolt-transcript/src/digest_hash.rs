//! The hash behind every digest a statement or a key binds.
//!
//! SHA3-256 (FIPS 202) by default. The `keccak256-digests` feature selects
//! Keccak-256 with the original `0x01` pad byte, the hash Ethereum uses, for
//! applications that need it. The two share Keccak-f[1600] and differ only in
//! that pad byte, so a guest with a Keccak permutation instruction pays the
//! same for either. Cargo unifies features across a build, so a build selects
//! exactly one. [`PROTOCOL_ID`](crate::PROTOCOL_ID) names the selection, so a
//! proof made under one never verifies under the other.

use core::fmt;
#[cfg(not(target_arch = "riscv64"))]
use keccak::Keccak;
use sha3::digest::{
    common::BlockSizeUser,
    consts::{U136, U32},
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
};
use sponge_cursor::SpongeCursor;

/// The hashes a build can select for its digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestHash {
    /// SHA3-256 (FIPS 202), the default.
    Sha3_256,
    /// Keccak-256 with the `0x01` pad byte, under `keccak256-digests`.
    Keccak256,
}

/// The digest hash this build selects.
#[cfg(not(feature = "keccak256-digests"))]
pub const DIGEST_HASH: DigestHash = DigestHash::Sha3_256;
/// The digest hash this build selects.
#[cfg(feature = "keccak256-digests")]
pub const DIGEST_HASH: DigestHash = DigestHash::Keccak256;

/// The hasher for [`DIGEST_HASH`], using the bare Keccak-f inline on RV64.
#[derive(Clone, Default)]
pub struct DigestHasher {
    state: [u64; 25],
    cursor: SpongeCursor<136>,
}

impl DigestHasher {
    #[expect(
        clippy::indexing_slicing,
        reason = "SpongeCursor<136> bounds the padding lane below 17; state has 25 lanes"
    )]
    fn finish(&mut self, output: &mut Output<Self>) {
        let suffix = match DIGEST_HASH {
            DigestHash::Sha3_256 => 0x06u64,
            DigestHash::Keccak256 => 0x01u64,
        };
        let pos = self.cursor.pos();
        self.state[pos / 8] ^= suffix << (8 * (pos % 8));
        self.state[16] ^= 1 << 63;
        permute(&mut self.state);
        for (bytes, lane) in output
            .as_mut_slice()
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(self.state)
        {
            *bytes = lane.to_le_bytes();
        }
    }
}

impl fmt::Debug for DigestHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DigestHasher { ... }")
    }
}

impl HashMarker for DigestHasher {}

impl BlockSizeUser for DigestHasher {
    type BlockSize = U136;
}

impl OutputSizeUser for DigestHasher {
    type OutputSize = U32;
}

impl Update for DigestHasher {
    fn update(&mut self, data: &[u8]) {
        self.cursor.absorb_u64_le(&mut self.state, permute, data);
    }
}

impl FixedOutput for DigestHasher {
    fn finalize_into(mut self, output: &mut Output<Self>) {
        self.finish(output);
    }
}

impl Reset for DigestHasher {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

impl FixedOutputReset for DigestHasher {
    fn finalize_into_reset(&mut self, output: &mut Output<Self>) {
        self.finish(output);
        Reset::reset(self);
    }
}

fn permute(state: &mut [u64; 25]) {
    #[cfg(target_arch = "riscv64")]
    jolt_inlines_keccak256::keccak_f1600(state);
    #[cfg(not(target_arch = "riscv64"))]
    Keccak::new().with_f1600(|permutation| permutation(state));
}

#[cfg(test)]
mod tests {
    use sha3::Digest;

    use super::{DigestHash, DigestHasher, DIGEST_HASH};

    /// FIPS 202 and Keccak team known answers for the empty input.
    #[test]
    fn digest_hasher_is_the_selected_hash() {
        let expected: [u8; 32] = match DIGEST_HASH {
            DigestHash::Sha3_256 => [
                0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
                0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
                0x80, 0xf8, 0x43, 0x4a,
            ],
            DigestHash::Keccak256 => [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70,
            ],
        };
        assert_eq!(DigestHasher::digest(b"")[..], expected);
    }

    #[cfg(not(feature = "keccak256-digests"))]
    #[test]
    fn sha3_rate_boundaries_and_split_updates() {
        // Frozen SHA3-256 vectors, independently generated with Python hashlib.
        let vectors = [
            (
                135,
                [
                    0xfd, 0xed, 0x8f, 0xd9, 0xd6, 0x55, 0x1c, 0x60, 0x1e, 0xeb, 0x3b, 0x7c, 0x6b,
                    0xc5, 0xe5, 0xcf, 0xd8, 0xaa, 0xd1, 0xd0, 0x15, 0xb7, 0xe9, 0xaa, 0xa9, 0xc9,
                    0xb9, 0x47, 0x52, 0x31, 0xd5, 0xe2,
                ],
            ),
            (
                136,
                [
                    0xcf, 0x3c, 0xcf, 0xf9, 0x24, 0x80, 0xa2, 0x91, 0x60, 0xc2, 0xd3, 0x83, 0x17,
                    0xc4, 0x30, 0xe1, 0x47, 0x49, 0xbf, 0xee, 0x17, 0x88, 0x10, 0x69, 0x57, 0xdf,
                    0xe7, 0x3f, 0x8c, 0x49, 0x30, 0xe5,
                ],
            ),
            (
                137,
                [
                    0xce, 0x9d, 0x7d, 0xc9, 0x09, 0x13, 0xee, 0x5d, 0x92, 0x74, 0x50, 0x19, 0x47,
                    0x9a, 0x53, 0x52, 0xc6, 0xd6, 0x27, 0x9b, 0xef, 0x18, 0xed, 0x07, 0xdc, 0x0a,
                    0x83, 0xee, 0x80, 0x84, 0xda, 0xca,
                ],
            ),
            (
                272,
                [
                    0xb7, 0xcc, 0xd5, 0x5b, 0x6c, 0x2c, 0x3f, 0xa1, 0x44, 0xc9, 0xe0, 0x62, 0x40,
                    0x59, 0x29, 0x49, 0x75, 0xa3, 0x48, 0xb0, 0x2f, 0x32, 0x1a, 0xbe, 0x28, 0x97,
                    0x01, 0xd3, 0x01, 0x2f, 0x77, 0x94,
                ],
            ),
        ];
        for (length, expected) in vectors {
            let input: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            for split in 0..=length {
                let (first, second) = input.split_at(split);
                let mut hasher = DigestHasher::new_with_prefix(first);
                hasher.update([]);
                hasher.update(second);
                let cloned = hasher.clone().finalize();
                let output = hasher.finalize_reset();
                assert_eq!(cloned, output);
                assert_eq!(
                    output.as_slice(),
                    expected,
                    "length {length}, split {split}"
                );
                hasher.update(b"abc");
                assert_eq!(
                    hasher.finalize().as_slice(),
                    [
                        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d,
                        0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
                        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
                    ]
                );
            }
        }
    }
}
