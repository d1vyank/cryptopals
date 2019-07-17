use std::{fs,str};
use crate::score::english_score;

/// Represents a possible value of a brute forced on a single byte xor cipher
#[derive(Default)]
pub struct BruteForceGuess {
    pub output: String,
    pub key: u8,
    pub score: u32,
}

/// Accepts two hexadecimal encoded strings of equal length and produces their XORed output
pub fn fixed_xor(input1: String, input2: String) -> Result<String, hex::FromHexError> {
    assert_eq!(input1.len(), input2.len(), "input lengths unequal");
    let i1 = hex::decode(input1)?;
    let i2 = hex::decode(input2)?;

    let out: Vec<u8> = i1.iter().zip(i2.iter()).map(|(x, y)| x ^ y).collect();

    Ok(hex::encode(out))
}

pub fn decrypt_single_byte_xor_cipher(input: String) -> Result<String, hex::FromHexError> {
    let bytes = hex::decode(input)?;
    let mut guesses = decrypt_single_byte_xor(bytes);
    score_decrypted_strings(&mut guesses);

    // return best guess
    Ok(guesses
        .last()
        .unwrap_or(&Default::default())
        .output
        .clone())
}

pub fn find_single_byte_xor_encrypted_string() -> Result<String, hex::FromHexError> {
    let contents = fs::read_to_string("./test_input/set1challenge4.txt").unwrap();
    let inputs = contents.split("\n");
    let mut results = vec![];
    for input in inputs {
        results.push(decrypt_single_byte_xor_cipher(input.to_string())?);
    }

    let mut best_score = 0;
    let mut best_guess = Default::default();
    for result in results {
        let score = english_score(&result);
        if score > best_score {
            best_score = score;
            best_guess = result;
        }
    }

    // return best guess
    Ok(best_guess.clone())
}

pub fn decrypt_single_byte_xor(bytes: Vec<u8>) -> Vec<BruteForceGuess> {
    let keys: Vec<u8> = (0b00000000..=0b11111111).collect();
    let mut guesses = vec![];

    // Brute force all possible decrypted values
    for key in keys.iter() {
        let decrypted_bytes: Vec<u8> = bytes.iter().map(|byte| byte ^ key).collect();
        let decrypted_string = match str::from_utf8(&decrypted_bytes) {
            Ok(v) => v.to_string(),
            // Ignore strings with invalid characters
            Err(_e) => continue,
        };
        guesses.push(BruteForceGuess{output: decrypted_string, key: key.clone(), score: 0});
    }

    guesses
}

pub fn score_decrypted_strings(guesses: &mut Vec<BruteForceGuess>) {
    // Score by maximum occurences of alphabets and spaces
    for g in guesses.iter_mut() {
        g.score = english_score(&g.output)
    }

    guesses.sort_by_key(|g| g.score);
}
