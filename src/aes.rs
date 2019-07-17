use openssl::error::ErrorStack;
use openssl::symm::{decrypt, Cipher};

pub fn decrypt_aes_128_ecb(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    decrypt(Cipher::aes_128_ecb(), key, None, bytes)
}

pub fn detect_aes_ecb(bytes: &[u8]) -> bool {
    for (i, _) in bytes.iter().enumerate().step_by(16) {
        for (j, _) in bytes.iter().enumerate().step_by(16) {
            if i == j {
                continue;
            }
            if bytes[i..i + 16] == bytes[j..j + 16] {
                return true;
            }
        }
    }
    false
}
