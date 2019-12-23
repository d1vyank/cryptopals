use flate2::write::ZlibEncoder;
use flate2::Compression;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use std::io::prelude::*;

use crate::aes128;
use crate::encoding;

fn compress(input: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(input).unwrap();
    e.finish().unwrap()
}

pub mod side_channel {
    use super::*;

    struct Oracle {
        rng: SmallRng,
    }

    impl Oracle {
        pub fn new() -> Self {
            Oracle {
                rng: SmallRng::seed_from_u64(1234),
            }
        }
        pub fn execute_stream_cipher(&mut self, body: &str) -> usize {
            let formatted_request = format_request(body);
            let compressed_formatted_request = compress(formatted_request.as_bytes());
            let encrypted_compressed_formatted_request = aes128::ctr::encrypt(
                &compressed_formatted_request,
                &self.rng.gen::<[u8; 16]>(),
                self.rng.gen(),
            )
            .unwrap();

            encrypted_compressed_formatted_request.len()
        }

        pub fn execute_block_cipher(&mut self, body: &str) -> usize {
            let formatted_request = format_request(body);
            let compressed_formatted_request = compress(formatted_request.as_bytes());
            let encrypted_compressed_formatted_request = aes128::cbc::encrypt(
                &compressed_formatted_request,
                &self.rng.gen::<[u8; 16]>(),
                &self.rng.gen::<[u8; 16]>(),
            )
            .unwrap();

            encrypted_compressed_formatted_request.len()
        }
    }

    pub fn attack_stream_cipher() -> String {
        let mut oracle = Oracle::new();
        let baseline = oracle.execute_stream_cipher("Cookie: sessionid=");
        let mut random_bytes = vec![];
        let mut guessed_byte = 0;
        // 44 is the session ID length
        for byte in 0..44 {
            random_bytes.push(0);
            for k in 0b00000000..=0b11111111 {
                random_bytes[byte] = k;
                let guess_len = oracle.execute_stream_cipher(
                    &("Cookie: sessionid=".to_owned() + &encoding::ascii_encode(&random_bytes)),
                );
                if guess_len <= baseline {
                    guessed_byte = k;
                }
            }
            random_bytes[byte] = guessed_byte;
        }

        encoding::ascii_encode(&random_bytes)
    }

    pub fn attack_block_cipher() -> String {
        let mut oracle = Oracle::new();
        let mut request_body: String = "Cookie: sessionid=".to_string();
        let baseline = oracle.execute_block_cipher(&request_body);

        // Find the edge of the block by prefixing single bytes of data
        // adding are guesses to the block boundary leaks the info we need to guess the session id
        for i in 1..=16 {
            request_body = i.to_string() + &request_body;
            if oracle.execute_block_cipher(&request_body) > baseline {
                request_body.remove(0);
                break;
            }
        }
        let mut session_id_bytes: Vec<u8> = vec![];
        // 44 is the session ID length
        for index in (0..44).step_by(2) {
            let mut guessed_bytes = 0;
            session_id_bytes.push(0);
            session_id_bytes.push(0);
            // we guess two bytes at a time to reduce the error margin
            for k in std::u16::MIN..=std::u16::MAX {
                session_id_bytes.splice(index..=(index + 1), k.to_be_bytes().iter().cloned());

                let guess_len = oracle.execute_stream_cipher(
                    &(request_body.clone() + &encoding::ascii_encode(&session_id_bytes)),
                );
                if guess_len <= baseline {
                    guessed_bytes = k;
                }
            }
            session_id_bytes.splice(
                index..=(index + 1),
                guessed_bytes.to_be_bytes().iter().cloned(),
            );
        }

        encoding::ascii_encode(&session_id_bytes)
    }

    fn format_request(body: &str) -> String {
        format!(
            "POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {:}
{:}",
            body.len(),
            body
        )
    }
}
