use spongefish::{DuplexSponge, Permutation};

/// Keccak-f[1600] over little-endian byte lanes, using Jolt's bare inline.
#[derive(Clone, Default)]
pub struct InlineKeccakF1600;

impl Permutation<200> for InlineKeccakF1600 {
    type U = u8;

    fn permute_mut(&self, state: &mut [u8; 200]) {
        let mut words = [0u64; 25];
        for (word, bytes) in words.iter_mut().zip(state.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
        jolt_inlines_keccak256::keccak_f1600(&mut words);
        for (bytes, word) in state.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *bytes = word.to_le_bytes();
        }
    }
}

/// Spongefish's byte duplex with its stock width, rate, and Keccak-f rounds.
pub type Keccak = DuplexSponge<InlineKeccakF1600, 200, 136>;
