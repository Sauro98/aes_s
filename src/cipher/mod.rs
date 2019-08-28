use crate::aes_matrix::AesMatrix;
use crate::key_manager::KeyManager;

mod cipher_test;

pub struct Cipher {
    key_manager: KeyManager,
}

impl Cipher {
    pub fn new_128(key: &[u32; 4]) -> Cipher {
        Cipher {
            key_manager: KeyManager::new_128(key),
        }
    }

    pub fn new_192(key: &[u32; 6]) -> Cipher {
        Cipher {
            key_manager: KeyManager::new_192(key),
        }
    }

    pub fn new_256(key: &[u32; 8]) -> Cipher {
        Cipher {
            key_manager: KeyManager::new_256(key),
        }
    }

    pub fn cipher(&mut self, input: &mut [u8; 16]) {
        AesMatrix::add_round_key_8(input, self.key_manager.next_words(0));
        for round in 0..self.key_manager.rounds() - 1 {
            AesMatrix::substitute_bytes_8(input);
            AesMatrix::shift_rows_8(input);
            AesMatrix::mix_columns_8(input);
            AesMatrix::add_round_key_8(input, self.key_manager.next_words((round + 1) * 4));
        }
        AesMatrix::substitute_bytes_8(input);
        AesMatrix::shift_rows_8(input);
        AesMatrix::add_round_key_8(
            input,
            self.key_manager.next_words(self.key_manager.rounds() * 4),
        );
    }

    pub fn decipher(&mut self, input: &mut [u8; 16]) {
        AesMatrix::add_round_key_8(
            input,
            self.key_manager.next_words(self.key_manager.rounds() * 4),
        );
        for round in (1..self.key_manager.rounds()).rev() {
            AesMatrix::inv_substitute_bytes_8(input);
            AesMatrix::inv_shift_rows_8(input);
            AesMatrix::inv_mix_columns_8(input);
            AesMatrix::add_round_key_8(input, self.key_manager.next_words_inv(round * 4));
        }
        AesMatrix::inv_substitute_bytes_8(input);
        AesMatrix::inv_shift_rows_8(input);
        AesMatrix::add_round_key_8(input, self.key_manager.next_words(0));
    }
}
