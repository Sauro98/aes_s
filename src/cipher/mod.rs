use crate::aes_matrix::AesMatrix;
use crate::key_manager::KeyManager;

mod cipher_test;

/**
 * Struct to cipher or decipher a 4x4 array of bytes given
 * a key, wich can be 4 words long (128 bits), 6 words long
 * (192 bits) or 8 words lorg (256 bit). Here word is intended
 * as 4 bytes (32 bits).  
 */
pub struct Cipher {
    key_manager: KeyManager,
}

impl Cipher {
    /**
     * Initializes the cipher based on key length
     */

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

    /**
     * Ciphers a 4x4 matrix of bytes in the format described in the 'aes_matrix'
     * module following the AES encryption standard. The procedure is the same regardless of key length
     */
    pub fn cipher(&self, input: &mut [u8; 16]) {
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

    /**
     * Deciphers a 4x4 matrix of bytes in the format described in the 'aes_matrix'
     * module following the AES encryption standard.
     * The procedure is the same regardless of key length.
     * This is not the straight decipher but what the AES documentation
     * refers to as the'equivalent inverse cipher'
     */
    pub fn decipher(&self, input: &mut [u8; 16]) {
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
