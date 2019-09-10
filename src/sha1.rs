use crypto::digest::Digest;
use crypto::sha1::{self, Sha1};
use num_bigint::BigUint;
use rand::rngs::SmallRng;
use rand::{thread_rng, Rng, SeedableRng};

use crate::encoding;

pub fn keyed_mac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.input(&[key, bytes].concat());
    let mut out = vec![0; hasher.output_bytes()];
    hasher.result(&mut out);

    out
}

pub fn hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.input(&bytes);
    let mut out = vec![0; hasher.output_bytes()];
    hasher.result(&mut out);

    out
}

pub mod length_extension_attack {
    use super::*;

    pub fn execute() -> (Vec<u8>, Vec<u8>) {
        for key_length_guess in 1..256 {
            let (forged_bytes, forged_mac) = execute_with_key_length(key_length_guess);
            if is_admin(&forged_bytes, &forged_mac) {
                return (forged_bytes, forged_mac);
            }
        }

        panic!("key length not found!");
    }

    pub fn execute_with_key_length(len: usize) -> (Vec<u8>, Vec<u8>) {
        let mac = oracle();

        // Prepend random data of 'secret key' len to calculate glue padding
        let mut message = known_string();
        let repeating_string: String = (0..(len)).map(|_| "A").collect();
        message.push_str(&repeating_string);
        let glue_padding = md_padding(message.as_bytes(), message.len() as u64);

        // find padding for the forged message
        let append_to_mac = ";admin=true".as_bytes();
        let final_len = message.len() + glue_padding.len() + append_to_mac.len();
        let append_to_mac = [append_to_mac, &md_padding(append_to_mac, final_len as u64)].concat();

        // create SHA1 state for original message
        let mut abcde = vec![];
        for (idx, _) in mac.iter().enumerate().step_by(4) {
            let x: [u8; 4] = [mac[idx], mac[idx + 1], mac[idx + 2], mac[idx + 3]];
            abcde.push(u32::from_be_bytes(x));
        }
        let mut state: [u32; 5] = [abcde[0], abcde[1], abcde[2], abcde[3], abcde[4]];

        // block by block, add additional data to SHA1 digest, starting from original message state
        for (idx, _) in append_to_mac.iter().enumerate().step_by(64) {
            sha1::sha1_digest_block(&mut state, &append_to_mac[idx..idx + 64]);
        }

        // collect state into final forged MAC vector
        let mut forged_mac = vec![];
        for s in state.iter() {
            for b in s.to_be_bytes().iter() {
                forged_mac.push(b.clone());
            }
        }
        let forged_bytes = [known_string().as_bytes(), &glue_padding, b";admin=true"].concat();
        (forged_bytes, forged_mac)
    }

    pub fn is_admin(message: &[u8], mac: &[u8]) -> bool {
        if encoding::ascii_encode(&message).contains(";admin=true")
            && keyed_mac(&secret_key(), &message) == mac
        {
            return true;
        }
        false
    }

    fn secret_key() -> Vec<u8> {
        let key: [u8; 16] = rand::rngs::SmallRng::seed_from_u64(1234).gen();
        key.to_vec()
    }

    fn known_string() -> String {
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_string()
    }

    fn oracle() -> Vec<u8> {
        keyed_mac(&secret_key(), known_string().as_bytes())
    }

    fn md_padding(buffer: &[u8], len: u64) -> Vec<u8> {
        let padding_len;
        let mut out = vec![];
        let mod_56 = buffer.len() % 56;
        if mod_56 == 0 {
            padding_len = 64;
        } else {
            padding_len = 56 + (8 * ((buffer.len() as f64) / 64.0).floor() as usize) - mod_56;
        }
        out.push(128);
        for _ in 0..(padding_len - 1) {
            out.push(0);
        }

        let len = len * 8;
        for b in len.to_be_bytes().iter() {
            out.push(*b);
        }

        out
    }
}
