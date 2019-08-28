use crate::aes_matrix::AesMatrix;
use crate::math::Math;

mod key_manager_test;

static ROUND_CONSTANT: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000,
];

pub struct KeyManager {
    rounds: usize,
    key: Vec<u32>,
    inverse_key: Vec<u32>,
}

impl KeyManager {
    pub fn new_128(in_key: &[u32; 4]) -> KeyManager {
        let (key, inverse_key) = Self::expand_key_128(in_key);
        KeyManager {
            rounds: 10,
            key,
            inverse_key,
        }
    }

    pub fn new_192(in_key: &[u32; 6]) -> KeyManager {
        let (key, inverse_key) = Self::expand_key_192(in_key);
        KeyManager {
            rounds: 12,
            key,
            inverse_key,
        }
    }

    pub fn new_256(in_key: &[u32; 8]) -> KeyManager {
        let (key, inverse_key) = Self::expand_key_256(in_key);
        KeyManager {
            rounds: 14,
            key,
            inverse_key,
        }
    }

    fn expand_key_128(key: &[u32; 4]) -> (Vec<u32>, Vec<u32>) {
        let nk = 4;
        let nr = 10;
        let mut expanded_key: Vec<u32> = Vec::new();
        for i in 0..nk {
            expanded_key.push(key[i]);
        }
        Self::populate_key_128_192(&mut expanded_key, nk, nr);
        let expanded_key_inverse = Self::produce_inverse_key(&expanded_key);
        (expanded_key, expanded_key_inverse)
    }

    fn expand_key_192(key: &[u32; 6]) -> (Vec<u32>, Vec<u32>) {
        let nk = 6;
        let nr = 12;
        let mut expanded_key: Vec<u32> = Vec::new();
        for i in 0..nk {
            expanded_key.push(key[i]);
        }
        Self::populate_key_128_192(&mut expanded_key, nk, nr);
        let expanded_key_inverse = Self::produce_inverse_key(&expanded_key);
        (expanded_key, expanded_key_inverse)
    }

    fn expand_key_256(key: &[u32; 8]) -> (Vec<u32>, Vec<u32>) {
        let mut expanded_key: Vec<u32> = Vec::new();
        for i in 0..8 {
            expanded_key.push(key[i]);
        }
        Self::populate_key_256(&mut expanded_key);
        let expanded_key_inverse = Self::produce_inverse_key(&expanded_key);
        (expanded_key, expanded_key_inverse)
    }

    fn produce_inverse_key(key: &Vec<u32>) -> Vec<u32> {
        let mut expanded_key_inverse = Vec::new();
        for word in key {
            let mut inv_words = [word.clone(), 0, 0, 0];
            AesMatrix::inv_mix_column_a(&mut inv_words, 0);
            expanded_key_inverse.push(inv_words[0]);
        }
        expanded_key_inverse
    }

    fn populate_key_128_192(key: &mut Vec<u32>, nk: usize, nr: usize) {
        for i in nk..(4 * (nr + 1)) {
            let mut temp = key[i - 1];
            if i % nk == 0 {
                Math::rot_word(&mut temp);
                Math::substitute_bytes_word(&mut temp);
                temp = temp ^ ROUND_CONSTANT[(i / nk) - 1];
            }
            let new_val = key[i - nk] ^ temp;
            key.push(new_val);
        }
    }

    fn populate_key_256(key: &mut Vec<u32>) {
        let nk = 8;
        let nr = 14;
        for i in nk..(4 * (nr + 1)) {
            let mut temp = key[i - 1];
            if i % nk == 0 {
                Math::rot_word(&mut temp);
                Math::substitute_bytes_word(&mut temp);
                temp = temp ^ ROUND_CONSTANT[(i / nk) - 1];
            } else if i % nk == 4 {
                Math::substitute_bytes_word(&mut temp);
            }
            let new_val = key[i - nk] ^ temp;
            key.push(new_val);
        }
    }

    pub fn key(&self) -> &Vec<u32> {
        &self.key
    }

    pub fn inv_key(&self) -> &Vec<u32> {
        &self.inverse_key
    }

    pub fn next_words(&self, base: usize) -> &[u32] {
        &self.key[base..base + 4]
    }

    pub fn next_words_inv(&self, base: usize) -> &[u32] {
        &self.inverse_key[base..base + 4]
    }

    pub fn rounds(&self) -> usize {
        self.rounds
    }
}
