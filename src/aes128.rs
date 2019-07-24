use openssl::error::ErrorStack;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng, SeedableRng};
use std::collections::HashMap;
use std::str;

use crate::score;

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

    pub fn detect(bytes: &[u8], block_size: usize) -> bool {
        for (i, _) in bytes.iter().enumerate().step_by(block_size) {
            for (j, _) in bytes.iter().enumerate().step_by(block_size) {
                if i == j {
                    continue;
                }
                if bytes[i..i + block_size] == bytes[j..j + block_size] {
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

pub fn decrypt_aes_ecb_byte_at_a_time() -> String {
    let block_size = detect_block_size();
    // Using long repeated input to detect ecb mode
    let long_repeating_string: String = (0..(2 * block_size)).map(|_| "A").collect();
    let is_ecb = ecb::detect(
        &ecb_encryption_oracle(long_repeating_string.as_bytes()).unwrap(),
        block_size,
    );


    if !is_ecb {
        panic!("only ecb mode supported");
    }

    // set of characters used for guessing plaintext bytes
    let charset: Vec<char> = score::english_char_set();
    // map of all possible values of the last byte of the block (which is the byte being decrypted)
    let mut guessed_blocks: HashMap<Vec<u8>, String>;
    let ciphertext_len = ecb_encryption_oracle(&[]).unwrap().len();
    // supply `block_size - 1` random bytes to oracle to be prepended to the
    // unknown string. this shifts the target byte to the end of the first block
    let mut oracle_input: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(block_size - 1)
        .collect();
    let mut plaintext: String = Default::default();
    let mut curr_decrypted_block: String = Default::default();


    // for each block in ciphertext
    for block_index in (0..ciphertext_len).step_by(block_size) {
        // for each byte in block
        for byte_index in 0..block_size {
            // construct map of all possible values of last byte and corresponding block ciphertexts
            guessed_blocks = HashMap::new();
            for c in charset.iter() {
                let guessed_plaintext =
                    oracle_input.to_string() + &curr_decrypted_block.to_string() + &c.to_string();
                let guessed_ciphertext =
                    ecb_encryption_oracle(guessed_plaintext.as_bytes()).unwrap();
                guessed_blocks.insert(
                    guessed_ciphertext[0..block_size].to_vec(),
                    guessed_plaintext,
                );
            }

            // supply prepared input to oracle
            let manipulated_ciphertext = &ecb_encryption_oracle(&oracle_input.as_bytes()).unwrap();
            // the prepared input manipulates the ciphertext by placing the byte we are trying to
            // guess at the end of the current block
            // pick the plaintext corresponding to the current block of the manipulated
            // ciphertext from the map of all possible ciphertexts and extract the last byte we
            // are targeting
            let decrypted_char = match guessed_blocks
                .get_mut(&manipulated_ciphertext[block_index..block_index + block_size])
            {
                Some(value) => value.pop().unwrap(),
                // We've hit padding, stop.
                None => break,
            };

            curr_decrypted_block.push(decrypted_char);
            // if we're not on the last byte in block, remove first byte of oracle input to shift
            // target byte left
            if byte_index != block_size - 1 {
                oracle_input = oracle_input[1..].to_string();
            }
        }

        oracle_input = curr_decrypted_block[1..].to_string();
        plaintext.push_str(&curr_decrypted_block);
        curr_decrypted_block = Default::default();
    }


    plaintext
}

fn detect_block_size() -> usize {
    let range = 3..=32;
    for i in range {
        // Generate input of 'i' bytes
        let mut repeated_input: String = Default::default();
        for _ in 0..(2 * i) {
            repeated_input.push('A');
        }

        let out = ecb_encryption_oracle(repeated_input.as_bytes()).unwrap();
        // take 'i' size blocks from output and check for repetition.
        if out[0..i] == out[i..(i + i)] {
            return i;
        }
    }
    panic!("block size not detected");
}

fn ecb_encryption_oracle(bytes: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let key: [u8; 16] = rand::rngs::StdRng::seed_from_u64(1234).gen();

    let mut unknown_string = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
    let mut bytes = bytes.to_vec();

    bytes.append(&mut unknown_string);

    return ecb::encrypt(&bytes, &key.to_vec());
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
    let n2: usize = rng.gen_range(5, 10);
    let mut values: [u8; 20] = rng.gen();
    bytes.splice(0..0, values[0..n1].iter().cloned());
    bytes.append(&mut values[10..10 + n2].to_vec());
}
