
use rand::{rngs, thread_rng, Rng, SeedableRng};
use std::collections::HashMap;
use url::form_urlencoded;

use crate::aes128;
use crate::encoding;

pub fn parse(s: String) -> HashMap<String, String> {
    form_urlencoded::parse(s.as_bytes()).into_owned().collect()
}

pub fn profile_for(email: String) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("email", &email)
        .append_pair("uid", "10")
        .append_pair("role", "user")
        .finish()
}

pub fn profile_oracle(email: String) -> Vec<u8> {
    encrypt_query_string(profile_for(email))
}

fn encrypt_query_string(query_string: String) -> Vec<u8> {
    let key: [u8; 16] = rngs::StdRng::seed_from_u64(1234).gen();
    aes128::ecb::encrypt(query_string.as_bytes(), &key).unwrap()
}

pub fn decrypt_profile_oracle(ciphertext: Vec<u8>) -> String {
    let key: [u8; 16] = rngs::StdRng::seed_from_u64(1234).gen();
    String::from_utf8(aes128::ecb::decrypt(&ciphertext, &key).unwrap()).unwrap()
}

pub fn generate_admin_profile() -> Vec<u8> {
    // find ciphertext for "admin" (padded to one block)
    let last_block_string =
        "admin\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}".to_string();
    let last_block = encrypt_query_string(last_block_string)[0..16].to_vec();

    // use 13 byte input so that 'user' is pushed to the last block and can be replaced by the
    // last block computed above
    // The generated query string will be: email=foo%40bar.com&uid=10&role=user
    let mut ciphertext = profile_oracle("foo@bar.com".to_string());
    ciphertext.splice(32..48, last_block.iter().cloned());

    ciphertext
}
