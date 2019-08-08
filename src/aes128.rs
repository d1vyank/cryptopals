use openssl::error::ErrorStack;
use rand::distributions::Alphanumeric;
use rand::rngs::SmallRng;
use rand::{thread_rng, Rng, SeedableRng};
use std::collections::HashMap;

use crate::encoding;
use crate::score;
use crate::xor;

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
    use openssl::symm;

    const BLOCK_SIZE: usize = 16;

    pub fn encrypt(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        assert_eq!(iv.len(), BLOCK_SIZE, "IV length must equal block size");

        let mut bytes = bytes.to_vec();
        encoding::pkcs7_encode(&mut bytes, BLOCK_SIZE);


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

        out = encoding::pkcs7_decode(&out, BLOCK_SIZE).unwrap();

        Ok(out)
    }

    pub fn decrypt_pad(
        bytes: &[u8],
        key: &[u8],
        iv: &[u8],
        pad: bool,
    ) -> Result<Vec<u8>, ErrorStack> {
        let mut out = vec![0; bytes.len() + 16];
        let mut decrypter = symm::Crypter::new(
            symm::Cipher::aes_128_cbc(),
            symm::Mode::Decrypt,
            key,
            Some(iv),
        )?;

        decrypter.pad(pad);
        decrypter.update(bytes, &mut out)?;

        Ok(out[0..bytes.len()].to_vec())
    }

    pub fn encrypt_pad(
        bytes: &[u8],
        key: &[u8],
        iv: &[u8],
        pad: bool,
    ) -> Result<Vec<u8>, ErrorStack> {
        let mut out = vec![0; bytes.len() + 16];
        let mut encrypter = symm::Crypter::new(
            symm::Cipher::aes_128_cbc(),
            symm::Mode::Encrypt,
            key,
            Some(iv),
        )?;

        encrypter.pad(pad);
        encrypter.update(bytes, &mut out)?;

        Ok(out[0..bytes.len()].to_vec())
    }
}

pub mod ctr {
    use super::ecb;
    use crate::xor;
    use openssl::error::ErrorStack;
    use rand::{Rng, SeedableRng};

    pub fn encrypt(bytes: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>, ErrorStack> {
        let block_size = 16;
        let mut ctr: u64 = 0;
        let mut ciphertext = vec![];

        // take block sized (or smaller) chunks of plaintext and xor with encrypted counter
        for (i, _) in bytes.iter().enumerate().step_by(block_size) {
            let block = [&nonce.to_le_bytes()[..], &ctr.to_le_bytes()[..]].concat();
            let encrypted_ctr = ecb::encrypt(&block, key)?;
            let mut end_index = i + block_size;
            if end_index >= bytes.len() {
                end_index = bytes.len();
            }

            let plaintext_block = &bytes[i..end_index];

            ciphertext.append(&mut xor::fixed_xor(
                plaintext_block,
                &encrypted_ctr[..plaintext_block.len()],
            ));
            ctr += 1;
        }

        Ok(ciphertext)
    }

    pub fn decrypt(bytes: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>, ErrorStack> {
        encrypt(bytes, key, nonce)
    }

    pub fn encrypt_fixed_nonce_key(bytes: &[u8]) -> Vec<u8> {
        let nonce = 0;
        let key: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(1234).gen();

        encrypt(bytes, &key, nonce).unwrap()
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
        &ecb_encryption_oracle(long_repeating_string.as_bytes()),
        block_size,
    );

    if !is_ecb {
        panic!("only ecb mode supported");
    }
    decrypt_aes_ecb(&ecb_encryption_oracle, block_size, 0)
}

pub fn decrypt_aes_ecb_padded_byte_at_a_time() -> String {
    let block_size = 16;
    let padding_size = detect_padding_size(block_size);


    decrypt_aes_ecb(&ecb_encryption_oracle_padded, block_size, padding_size)
}


fn decrypt_aes_ecb(
    oracle: &Fn(&[u8]) -> Vec<u8>,
    block_size: usize,
    padding_size: usize,
) -> String {
    let mut num_padding_blocks: usize = padding_size / block_size;
    let remaining_padding_bytes = padding_size % block_size;
    let mut prefix_string: String = Default::default();

    if remaining_padding_bytes != 0 {
        num_padding_blocks += 1;
        prefix_string = (0..(block_size - remaining_padding_bytes))
            .map(|_| "A")
            .collect();
    }

    let ciphertext_len = oracle(&[]).len() - padding_size;
    // set of characters used for guessing plaintext bytes
    let charset: Vec<char> = score::english_char_set();
    // map of all possible values of the last byte of the block (which is the byte being decrypted)
    let mut guessed_blocks: HashMap<Vec<u8>, String>;
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
                    oracle((prefix_string.clone() + &guessed_plaintext).as_bytes());
                guessed_blocks.insert(
                    guessed_ciphertext[num_padding_blocks * block_size
                        ..(num_padding_blocks * block_size) + block_size]
                        .to_vec(),
                    guessed_plaintext,
                );
            }

            // supply prepared input to oracle
            let mut manipulated_ciphertext =
                oracle((prefix_string.clone() + &oracle_input).as_bytes());
            manipulated_ciphertext =
                manipulated_ciphertext[num_padding_blocks * block_size..].to_vec();

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

        if curr_decrypted_block.len() == 0 {
            break;
        }
        oracle_input = curr_decrypted_block[1..].to_string();
        plaintext.push_str(&curr_decrypted_block);
        curr_decrypted_block = Default::default();
    }


    plaintext
}

fn detect_padding_size(block_size: usize) -> usize {
    // Use three blocks worth of reepeating bytes and find what the corresponding
    // ciphertext looks like
    let long_repeating_string: String = (0..(3 * block_size)).map(|_| "A").collect();
    let mut our_block = vec![];
    let bytes = ecb_encryption_oracle_padded(long_repeating_string.as_bytes());
    for (i, _) in bytes.iter().enumerate().step_by(block_size) {
        for (j, _) in bytes.iter().enumerate().step_by(block_size) {
            if i == j {
                continue;
            }
            if bytes[i..i + block_size] == bytes[j..j + block_size] {
                our_block = bytes[i..i + block_size].to_vec();
            }
        }
    }

    // Now find min number of repeating bytes required to produce ciphertext corresponding to
    // 'our_block'
    let mut long_repeating_string: String = (0..(2 * block_size)).map(|_| "A").collect();
    let mut our_block_offset = 0;
    let padding_size;
    let mut block_found;
    loop {
        block_found = false;
        let bytes = ecb_encryption_oracle_padded(long_repeating_string.as_bytes());
        for (i, _) in bytes.iter().enumerate().step_by(block_size) {
            if bytes[i..i + block_size] == our_block[..] {
                our_block_offset = i;
                block_found = true;
            }
        }

        if !block_found {
            padding_size = our_block_offset + block_size - long_repeating_string.len() - 1;

            break;
        }
        long_repeating_string.pop();
    }

    padding_size
}

fn detect_block_size() -> usize {
    let range = 3..=32;
    for i in range {
        // Generate input of 'i' bytes
        let mut repeated_input: String = Default::default();
        for _ in 0..(2 * i) {
            repeated_input.push('A');
        }

        let out = ecb_encryption_oracle(repeated_input.as_bytes());
        // take 'i' size blocks from output and check for repetition.
        if out[0..i] == out[i..(i + i)] {
            return i;
        }
    }
    panic!("block size not detected");
}

fn ecb_encryption_oracle(bytes: &[u8]) -> Vec<u8> {
    let key: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(1234).gen();

    let mut unknown_string = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
    let mut bytes = bytes.to_vec();

    bytes.append(&mut unknown_string);

    return ecb::encrypt(&bytes, &key.to_vec()).unwrap();
}

// Prefixes a random but constant number of random bytes to the input provided to the oracle
fn ecb_encryption_oracle_padded(bytes: &[u8]) -> Vec<u8> {
    let n: usize = SmallRng::seed_from_u64(123456).gen_range(0, 40);
    let mut padding = vec![];
    for i in 0..n {
        padding.push(SmallRng::seed_from_u64(i as u64).gen());
    }
    padding.extend_from_slice(bytes);
    ecb_encryption_oracle(&padding)
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

pub fn cbc_bitflipping_attack() -> Vec<u8> {
    let dummy_data_block = "AAAAAAAAAAAAAAAA".to_string();
    // Insert two blocks of user data. We manipulate the ciphertext of the first one
    // to flip bits on the second one to get the desired output.
    let mut ciphertext =
        cbc_bitflipping_oracle(dummy_data_block.clone() + &dummy_data_block.clone());
    let expected_output = "AAAAA;admin=true".as_bytes();

    let mut manipulated_ciphertext;
    manipulated_ciphertext = xor::fixed_xor(dummy_data_block.as_bytes(), expected_output);
    manipulated_ciphertext = xor::fixed_xor(&ciphertext[32..48].to_vec(), &manipulated_ciphertext);
    ciphertext.splice(32..48, manipulated_ciphertext);

    ciphertext
}

pub fn is_bitflipped_ciphertext_admin(input: Vec<u8>) -> bool {
    // Random but constant key and iv ( same as encrypt )
    let key: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(1234).gen();
    let iv: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(4321).gen();

    let input = cbc::decrypt(&input, &key, &iv).unwrap();
    let input: String = input.iter().map(|v| v.clone() as char).collect();
    input.contains(";admin=true;")
}

fn cbc_bitflipping_oracle(input: String) -> Vec<u8> {
    // Random but constant key and iv
    let key: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(1234).gen();
    let iv: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(4321).gen();

    let input = input.replace("=", "%3D");
    let input = input.replace(";", "%3B");

    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    let output = prefix.to_owned() + &input + suffix;

    cbc::encrypt(output.as_bytes(), &key, &iv).unwrap()
}

pub mod cbc_padding_oracle_attack {

    use crate::encoding;

    use rand::Rng;
    use rand::SeedableRng;
    use std::fs;

    pub fn execute() -> String {
        let (mut ciphertext, iv) = oracle();
        let ciphertext_len = ciphertext.len();
        let num_blocks = ciphertext_len / 16;

        let mut plaintext = vec![];
        let mut decrypted_block = vec![];
        let mut intermediate = vec![];

        // prepend IV to ciphertext (this is used to decrypt the first block)
        ciphertext.splice(0..0, iv.to_vec().iter().cloned());

        // For each block (starting from the second last, going backwards)
        for blk in (1..=num_blocks).rev() {
            // for each byte
            for target_byte in (0..16).rev() {
                // pick current and next block
                let mut manipulated_block = vec![0; 16];
                let target_block = ciphertext[(blk * 16)..(blk * 16) + 16].to_vec();
                // The target valid padding we're trying to produce.
                // e.g. 0x01 for byte 15, 0x02 for byte 14 .. 0x10 (16) for byte 0
                let target_padding = (16 - target_byte) as u8;
                // brute force all possible values for current byte
                for guess in 0b00000000..=0b11111111 {
                    manipulated_block[target_byte] = guess;
                    // set each preceding byte
                    for i in 0..intermediate.len() {
                        manipulated_block[15 - i] = intermediate[i] ^ target_padding;
                    }


                    let input = [&manipulated_block[..], &target_block[..]].concat();
                    if validate(input) {
                        decrypted_block.push(
                            guess ^ target_padding ^ ciphertext[(blk * 16) - (16 - target_byte)],
                        );
                        intermediate.push(guess ^ target_padding);
                        break;
                    }

                }
            }
            plaintext.splice(0..0, decrypted_block.iter().rev().cloned());
            decrypted_block = vec![];
            intermediate = vec![];
        }

        let plaintext = encoding::pkcs7_decode(&plaintext, 16).unwrap();

        plaintext.iter().map(|v| v.clone() as char).collect()
    }

    fn oracle() -> (Vec<u8>, [u8; 16]) {
        let key: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(1234).gen();
        let iv: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(4321).gen();

        let strings: Vec<String> = fs::read_to_string("./test_input/set3_challenge17.txt")
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect();

        let chosen_string = &strings[rand::thread_rng().gen_range(0, 9)];

        (
            super::cbc::encrypt(chosen_string.as_bytes(), &key, &iv).unwrap(),
            iv,
        )
    }

    fn validate(bytes: Vec<u8>) -> bool {
        let key: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(1234).gen();
        let iv: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(4321).gen();

        let mut decrypted_bytes = super::cbc::decrypt_pad(&bytes, &key, &iv, false).unwrap();
        let result = encoding::pkcs7_decode(&mut decrypted_bytes, 16);
        if result.is_err() {
            return false;
        }

        true
    }
}

pub fn attack_fixed_nonce_ctr_ciphertexts(ciphertexts: Vec<Vec<u8>>) -> Vec<u8> {
    let max_len = ciphertexts.iter().max_by_key(|c| c.len()).unwrap().len();
    let mut keystream = vec![];
    // for each column
    for i in 0..max_len {
        let mut column = vec![];
        // take the i'th byte of each ciphertext, if exists
        for c in ciphertexts.iter() {
            if c.len() <= i {
                continue;
            }
            column.push(c[i]);
        }
        // Each column is encrypted with the same byte of the key stream
        let mut guesses = xor::decrypt_single_byte_xor(column);
        // For the first column, use is_uppercase charater as the scoring function
        let mut heuristic: fn(&String) -> u32 = score::english_score;
        if i == 0 {
            heuristic = score::uppercase_score;
        }

        xor::score_decrypted_strings(&mut guesses, heuristic);
        keystream.push(guesses.last().unwrap_or(&Default::default()).key.clone());
    }

    keystream
}
