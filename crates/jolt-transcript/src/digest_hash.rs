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
    consts::{U32, U136},
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
        for (bytes, lane) in output.as_mut_slice().as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
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
            (135, "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2"),
            (136, "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5"),
            (137, "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca"),
            (272, "b7ccd55b6c2c3fa144c9e0624059294975a348b02f321abe289701d3012f7794"),
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
                let hex: String = output.iter().map(|byte| format!("{byte:02x}")).collect();
                assert_eq!(hex, expected, "length {length}, split {split}");
                hasher.update(b"abc");
                let hex: String = hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
                assert_eq!(hex, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
            }
        }
    }
}
