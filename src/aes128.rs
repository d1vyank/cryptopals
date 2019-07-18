use openssl::error::ErrorStack;
use rand::Rng;

pub mod ecb {
    use openssl::error::ErrorStack;
    use openssl::symm;

    pub fn decrypt(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        symm::decrypt(symm::Cipher::aes_128_ecb(), key, None, bytes)
    }

    pub fn encrypt(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        symm::encrypt(symm::Cipher::aes_128_ecb(), key, None, bytes)
    }

    pub fn decrypt_pad(bytes: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, ErrorStack> {
        let mut out = vec![0; bytes.len() + 16];
        let mut decrypter =
            symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Decrypt, key, None)?;

        decrypter.pad(pad);
        decrypter.update(bytes, &mut out)?;

        Ok(out[0..bytes.len()].to_vec())
    }

    pub fn encrypt_pad(bytes: &[u8], key: &[u8], pad: bool) -> Result<Vec<u8>, ErrorStack> {
        let mut out = vec![0; bytes.len() + 16];
        let mut encrypter =
            symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Encrypt, key, None)?;

        encrypter.pad(pad);
        encrypter.update(bytes, &mut out)?;

        Ok(out[0..bytes.len()].to_vec())
    }

    pub fn detect(bytes: &[u8]) -> bool {
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
}

pub mod cbc {
    use super::ecb;
    use crate::encoding;
    use crate::xor;
    use openssl::error::ErrorStack;

    const BLOCK_SIZE: usize = 16;

    pub fn encrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        assert_eq!(iv.len(), BLOCK_SIZE, "IV length must equal block size");

        let mut bytes = bytes.to_vec();
        if bytes.len() % 16 != 0 {
            encoding::pkcs7_encode(&mut bytes, BLOCK_SIZE);
        }

        let mut out = vec![];
        let mut prev_block = iv.to_vec();

        for (i, _) in bytes.iter().enumerate().step_by(BLOCK_SIZE) {
            let mut ciphertext = ecb::encrypt_pad(
                &xor::fixed_xor(&prev_block, &bytes[i..i + BLOCK_SIZE]),
                key,
                false,
            )?;
            prev_block = ciphertext[0..BLOCK_SIZE].to_vec();
            out.append(&mut ciphertext);
        }

        Ok(out)
    }

    pub fn decrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        assert_eq!(iv.len(), BLOCK_SIZE, "IV length must equal block size");

        let bytes = bytes.to_vec();

        let mut out = vec![];
        let mut prev_block = iv.to_vec();

        for (i, _) in bytes.iter().enumerate().step_by(BLOCK_SIZE) {
            let current_byte = bytes[i..i + BLOCK_SIZE].to_vec();
            let intermediate = ecb::decrypt_pad(&current_byte, key, false)?;
            let mut plaintext = xor::fixed_xor(&intermediate, &prev_block);
            prev_block = bytes[i..i + BLOCK_SIZE].to_vec().clone();
            out.append(&mut plaintext);
        }

        encoding::pkcs7_decode(&mut out, BLOCK_SIZE);

        Ok(out)
    }

}

pub fn encryption_oracle(bytes: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut rng = rand::thread_rng();
    let use_ecb: bool = rng.gen();
    let key = random_aes_key();
    let mut bytes = bytes.to_vec();
    random_padding(&mut bytes);

    if use_ecb {
        return ecb::encrypt(&bytes, &key);
    } else {
        let iv = random_aes_key();
        return cbc::encrypt(&bytes, &key, &iv);
    }
}

/// Generates a random 16 byte key
fn random_aes_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut out = vec![];
    for _ in 0..16 {
        out.push(rng.gen::<u8>());
    }
    out
}

/// Appends and prepends 5 to 10 bytes of random data to the given vector
fn random_padding(bytes: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();
    let n1: usize = rng.gen_range(5, 10);
    let mut values: [u8; 15] = rng.gen();
    bytes.splice(0..0, values[0..n1].iter().cloned());
    bytes.append(&mut values[n1..].to_vec());
}
