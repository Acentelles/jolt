use crate::{forward, DEGREE, MERGED_FUNCT7};

/// Immutable sign-extended digits, prepared once and reused across CRT limbs.
/// Private storage preserves the signed-i16 range required by merged transforms.
#[derive(Debug)]
#[repr(C, align(8))]
pub struct CenteredI16NttInput {
    words: [u64; DEGREE / 2],
}

impl CenteredI16NttInput {
    pub fn new(digits: &[i16; DEGREE]) -> Self {
        let word = |value: i16| u64::from(i32::from(value) as u32);
        Self {
            words: core::array::from_fn(|i| word(digits[2 * i]) | (word(digits[2 * i + 1]) << 32)),
        }
    }

    /// Overwrite every output word with its original signed digit.
    #[inline]
    pub fn write_to(&self, state: &mut [i32; DEGREE]) {
        let ptr = state.as_mut_ptr();
        if cfg!(target_endian = "little") && (ptr as usize).is_multiple_of(8) {
            #[expect(clippy::cast_ptr_alignment, reason = "The guard checks alignment")]
            let words = ptr.cast::<u64>();
            // SAFETY: the exclusive array covers exactly 32 doublewords and
            // the guard establishes alignment and little-endian lane order.
            unsafe { words.cast::<[u64; DEGREE / 2]>().write(self.words) };
        } else {
            for (pair, &word) in state.chunks_exact_mut(2).zip(&self.words) {
                pair[0] = word as i32;
                pair[1] = (word >> 32) as i32;
            }
        }
    }
}

#[derive(Debug)]
#[repr(C, align(8))]
struct MergedTwiddles([i32; DEGREE]);

/// Checked root tables for repeated forward transforms of signed-i16 digits.
///
/// Construction validates the numeric domain, root powers and final range once.
/// The typed input enforces the digit range, and every output word equals
/// `forward_ntt64` with the original tables. Use the raw entry point when
/// construction returns `None`.
#[derive(Debug)]
#[repr(C, align(8))]
pub struct PreparedForwardNtt64<'a> {
    merged: MergedTwiddles,
    psi: &'a [i32; DEGREE],
    twiddles: &'a [i32; DEGREE],
    p: i32,
    pinv: i32,
}

impl<'a> PreparedForwardNtt64<'a> {
    /// Admit odd `0 < p < 2^30`, its inverse modulo `2^32`, tables in `(-p,p)`,
    /// root-structured twist/stage tables and a final scale satisfying the
    /// checked six-stage bound. Original tables stay immutably borrowed for
    /// portable execution; the merged stage table is owned.
    pub fn new(
        psi: &'a [i32; DEGREE],
        twiddles: &'a [i32; DEGREE],
        p: i32,
        pinv: i32,
    ) -> Option<Self> {
        if p <= 0 || p >= 1 << 30 || p & 1 == 0 || p.wrapping_mul(pinv) != 1 {
            return None;
        }
        if psi
            .iter()
            .chain(twiddles)
            .any(|&value| value <= -p || value >= p)
        {
            return None;
        }
        let one = ((1u64 << 32) % p as u64) as i32;
        if twiddles[0] != one && twiddles[0] != one - p {
            return None;
        }
        let merged = Self::merged_table(psi, twiddles, p, pinv)?;
        Some(Self {
            merged,
            psi,
            twiddles,
            p,
            pinv,
        })
    }

    /// Transform typed signed-i16 digits, overwriting every output word.
    /// Hosts execute the portable transform using the original tables.
    #[inline]
    pub fn transform_i16(&self, input: &CenteredI16NttInput, state: &mut [i32; DEGREE]) {
        input.write_to(state);
        let twiddles = if cfg!(target_arch = "riscv64") {
            &self.merged.0
        } else {
            self.twiddles
        };
        forward::<MERGED_FUNCT7>(state, self.psi, twiddles, self.p, self.pinv);
    }

    fn merged_table(
        psi: &[i32; DEGREE],
        twiddles: &[i32; DEGREE],
        p: i32,
        pinv: i32,
    ) -> Option<MergedTwiddles> {
        let modulus = p as u64;
        let radix = 1u64 << 32;
        let one = radix % modulus;
        let residue = |value: i32| value.rem_euclid(p) as u64;
        let center = |value: u64| {
            if value > modulus / 2 {
                value as i32 - p
            } else {
                value as i32
            }
        };
        if residue(psi[0]) != one * one % modulus {
            return None;
        }
        // p*pinv = 1 + k*R, so -k is R^-1 modulo every admitted odd p.
        // This also defines zero residues when p=1, without primality.
        let k = (modulus * u64::from(pinv as u32) - 1) >> 32;
        let inverse = (modulus - k % modulus) % modulus;
        let root = residue(psi[1]) * inverse % modulus * inverse % modulus;
        let mut powers = [0u64; DEGREE];
        let mut power = 1 % modulus;
        for (i, slot) in powers.iter_mut().enumerate() {
            *slot = power;
            if residue(psi[i]) != power * one % modulus * one % modulus {
                return None;
            }
            power = power * root % modulus;
        }
        if power != modulus - 1 {
            return None;
        }
        for len in [1, 2, 4, 8, 16, 32] {
            for j in 0..len {
                if residue(twiddles[len - 1 + j]) != powers[DEGREE / len * j] * one % modulus {
                    return None;
                }
            }
        }
        let scale = center(residue(psi[0]));
        let mut bound = 32768u64;
        for _ in 0..6 {
            bound += (bound * (modulus / 2)).div_ceil(radix) + modulus.div_ceil(2);
        }
        // The six butterfly bounds are below 2R, so all products fit i64.
        // This additional strict bound makes the final result lie in (-p,p).
        if 2 * bound * u64::from(scale.unsigned_abs()) >= modulus * radix {
            return None;
        }
        Some(MergedTwiddles(core::array::from_fn(|i: usize| {
            if i == 0 {
                scale
            } else {
                center(powers[i.reverse_bits() >> (usize::BITS - 6)] * one % modulus)
            }
        })))
    }
}

#[cfg(all(test, feature = "host"))]
#[path = "prepared_tests.rs"]
mod tests;
