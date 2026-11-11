use crate::{forward, DEGREE, LAZY_FUNCT7};

/// Checked tables for repeated forward transforms with alternating lazy stages.
///
/// Construction validates the numeric domain once. Every subsequent transform
/// accepts all signed-word state values and returns exactly the canonical words
/// of `forward_ntt64` with the original tables. Table roots are not required for
/// this equivalence. Keep the raw entry point when construction returns `None`.
#[derive(Debug)]
#[repr(C, align(8))]
pub struct PreparedForwardNtt64<'a> {
    twiddles: [i32; DEGREE],
    psi: &'a [i32; DEGREE],
    p: i32,
    pinv: i32,
}

impl<'a> PreparedForwardNtt64<'a> {
    /// Admit odd `0 < p < 2^30`, its inverse modulo `2^32`, tables in `(-p,p)`,
    /// and a first stage twiddle congruent to `2^32` modulo `p`.
    /// The centered stage table is owned; the twist table stays immutably borrowed.
    pub fn new(
        psi: &'a [i32; DEGREE],
        twiddles: &[i32; DEGREE],
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
        let twiddles = twiddles.map(|value| {
            let canonical = if value < 0 { value + p } else { value };
            if canonical > p / 2 {
                canonical - p
            } else {
                canonical
            }
        });
        Some(Self {
            twiddles,
            psi,
            p,
            pinv,
        })
    }

    /// Transform any signed-word state; unaligned arrays use aligned buffers.
    #[inline]
    pub fn transform(&self, state: &mut [i32; DEGREE]) {
        forward::<LAZY_FUNCT7>(state, self.psi, &self.twiddles, self.p, self.pinv);
    }
}

#[cfg(all(test, feature = "host"))]
#[path = "prepared_tests.rs"]
mod tests;
