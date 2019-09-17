use crate::sha1;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

pub fn compute(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let block_size = 64;
    let mut key = key.to_vec();
    if key.len() > block_size {
        key = sha1::hash(&key);
    }

    if key.len() < block_size {
        key = zero_pad(&key, block_size - key.len());
    }

    let o_key_pad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
    let i_key_pad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();

    sha1::hash(&[o_key_pad, sha1::hash(&[&i_key_pad, bytes].concat())].concat())
}

pub mod timing_attack_1 {
    use super::*;
    use rocket::http::Status;
    use rocket::local::Client;
    use rocket::Rocket;
    use std::thread;
    use std::time::{self, SystemTime};

    pub fn execute(file: String) -> String {
        let client = Client::new(web_server()).unwrap();
        let timed_request = |h: &[u8]| {
            thread::sleep(time::Duration::from_millis(100));
            let before = SystemTime::now();
            let _ = client
                .get(format!("/test/{}/{}", file, hex::encode(h)))
                .dispatch();
            let after = SystemTime::now();
            after.duration_since(before).unwrap().as_millis() as f32
        };
        let averaged_timed_request = |h: &[u8]| {
            let mut sum = 0.0;
            for _ in 0..32 {
                sum += timed_request(h);
            }
            sum / 32.0
        };
        let mut hmac = vec![0; 20];

        for i in 0..hmac.len() {
            let mut found = false;

            let avg_overhead = averaged_timed_request(&hmac);
            for byte in std::u8::MIN..=std::u8::MAX {
                hmac[i] = byte;
                let avg_response_time = averaged_timed_request(&hmac);
                if (avg_response_time - avg_overhead) >= 4.5 {
                    found = true;
                    break;
                }
            }
            if !found {
                hmac[i] = 0;
            }
        }

        hex::encode(hmac)
    }

    fn web_server() -> Rocket {
        rocket::ignite().mount("/", routes![validate])
    }
    #[get("/test/<file>/<signature>")]
    fn validate(file: String, signature: String) -> Status {
        let hmac = compute(&key(), file.as_bytes());

        let signature = match hex::decode(signature) {
            Ok(value) => value,
            Err(_e) => {
                return Status::InternalServerError;
            }
        };

        if signature.len() != hmac.len() || !insecure_compare(&hmac, &signature) {
            return Status::InternalServerError;
        }

        Status::Ok
    }

    fn insecure_compare(hmac: &[u8], signature: &[u8]) -> bool {
        for (i, byte) in hmac.iter().enumerate() {
            if byte != &signature[i] {
                return false;
            }

            thread::sleep(time::Duration::from_millis(5));
        }
        true
    }

    pub fn key() -> Vec<u8> {
        SmallRng::seed_from_u64(1234).gen::<[u8; 32]>().to_vec()
    }
}

fn zero_pad(x: &[u8], len: usize) -> Vec<u8> {
    let padding = vec![0; len];
    [x, &padding].concat()
}

#[test]
fn hmac_compute() {
    let hmac = compute(
        &SmallRng::seed_from_u64(1234).gen::<[u8; 32]>(),
        "foo".as_bytes(),
    );
    assert_eq!(
        "dea3f511e5baa6b483da601a5ad43b03d9cbb4cf",
        hex::encode(&hmac)
    );

    let hmac = compute(
        "key".as_bytes(),
        "The quick brown fox jumps over the lazy dog".as_bytes(),
    );
    assert_eq!(
        "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
        hex::encode(&hmac)
    );
}
