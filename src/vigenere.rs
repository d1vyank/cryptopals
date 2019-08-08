use crate::xor;
use crate::score;

use std::collections::hash_map::HashMap;
pub fn repeating_key_xor(input: String) -> String {
    let bytes = input.into_bytes();
    let mut output = vec![];
    for (i, byte) in bytes.iter().enumerate() {
        if i % 3 == 0 {
            output.push(byte ^ "I".as_bytes().first().unwrap());
        }
        if i % 3 == 1 {
            output.push(byte ^ "C".as_bytes().first().unwrap());
        }
        if i % 3 == 2 {
            output.push(byte ^ "E".as_bytes().first().unwrap());
        }
    }

    hex::encode(&output)
}

pub fn break_repeating_key_xor(input: String) -> Result<Vec<u8>, base64::DecodeError> {
    let key_size_guess_range = 2..=40;
    let bytes = base64::decode(&input.lines().collect::<String>())?;
    let mut distance_min = u32::max_value();
    let mut probable_key_size = Default::default();
    for key_size_guess in key_size_guess_range {
        let mut h = 0;
        // Take bytes 'key size' blocks at a time
        let num_blocks = bytes.len() / key_size_guess;
        let last_block_index = num_blocks * key_size_guess;
        for i in (key_size_guess..=last_block_index - key_size_guess).step_by(key_size_guess) {
            h += hamming_distance(&bytes[0..key_size_guess], &bytes[i..i + key_size_guess]);
        }

        // average
        h = h / (bytes.len() / key_size_guess) as u32;
        // normalize
        h = h / key_size_guess as u32;

        if h < distance_min {
            distance_min = h;
            probable_key_size = key_size_guess;
        }
    }

    Ok(break_repeating_key_xor_with_key_size(bytes, probable_key_size))
}

pub fn break_repeating_key_xor_with_key_size(
    bytes: Vec<u8>,
    key_size: usize,
) -> Vec<u8> {
    let mut possible_keys: Vec<HashMap<u8, u32>> = vec![HashMap::new(); key_size];
    for (i, byte) in bytes.iter().enumerate() {

        let mut guesses = xor::decrypt_single_byte_xor(vec![byte.clone()]);
        xor::score_decrypted_strings(&mut guesses, score::english_score);
        let best_guess = match guesses.last() {
            Some(v) => v,
            None => continue,
        };
        let best_key_guess = best_guess.key;
        match possible_keys[i % key_size].get_mut(&best_key_guess) {
            Some(value) => *value += 1,
            None => {
                let _ = possible_keys[i % key_size].insert(best_key_guess, 1);
            }
        };
    }

    let mut key = vec![];
    for k in possible_keys.iter() {
        let mut temp: Vec<(&u8, &u32)> = k.iter().collect();
        temp.sort_by(|a, b| b.1.cmp(a.1));
        key.push(temp[0].0.clone());
    }

    key
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    if a.len() != b.len() {
        panic!("cannot find hamming distance for items of unequal lengths");
    }
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

#[test]
fn test_hamming_distance() {
    assert_eq!(
        37,
        hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes())
    );
}
