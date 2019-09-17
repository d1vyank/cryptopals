use crate::bits;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use std::time::{Duration, SystemTime};

const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;
const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;
const R: u32 = 31;

pub struct MersenneRng {
    index: usize,
    state: Vec<u32>,
}

impl MersenneRng {
    // Initialize the generator from a seed
    pub fn new(seed: u32) -> Self {
        let mut state = vec![seed];
        for i in 1..=(N - 1) {
            let val: u64 = (1812433253 as u64) * (state[i - 1] ^ (state[i - 1] >> (W - 2))) as u64
                + (i as u64);
            state.push(val as u32);
        }
        MersenneRng {
            index: N,
            state: state,
        }
    }

    pub fn clone(samples: Vec<u32>) -> Self {
        if samples.len() != N {
            panic!("{:?} samples required to clone", N);
        }

        MersenneRng {
            index: N,
            state: samples.iter().map(|n| untemper(*n)).collect(),
        }
    }

    // Extract a tempered value based on state[index]
    // calling twist() every N numbers
    pub fn extract_number(&mut self) -> u32 {
        if self.index == N {
            self.twist();
        }

        let y = temper(self.state[self.index]);
        self.index += 1;

        y
    }

    // Generate the next N values from the series x_i
    fn twist(&mut self) {
        for i in 0..(N - 1) {
            let x = (self.state[i] & UPPER_MASK) + (self.state[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if (x % 2) != 0 {
                // lowest bit of x is 1
                x_a = x_a ^ 0x9908B0DF;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }
        self.index = 0;
    }
}

fn temper(y: u32) -> u32 {
    let mut y = y ^ (y >> 11);
    y ^= (y << 7) & 0x9D2C5680;
    y ^= (y << 15) & 0xEFC60000;
    y ^ (y >> 18)
}

fn untemper(y: u32) -> u32 {
    let mut y = bits::invert_right_shift_xor(18, y);
    y = bits::invert_left_shift_and_xor(15, y, 0xEFC60000);
    y = bits::invert_left_shift_and_xor(7, y, 0x9D2C5680);
    bits::invert_right_shift_xor(11, y)
}

pub fn mt_cipher_encrypt(key: u16, bytes: &[u8]) -> Vec<u8> {
    let mut rng = MersenneRng::new(key as u32);
    let mut keystream = vec![];
    let mut out = vec![];
    for byte in bytes.iter() {
        if keystream.len() == 0 {
            keystream = rng.extract_number().to_be_bytes().to_vec();
        }
        out.push(byte ^ keystream.pop().unwrap());
    }

    out
}

pub fn mt_cipher_decrypt(key: u16, bytes: &[u8]) -> Vec<u8> {
    mt_cipher_encrypt(key, bytes)
}

pub fn break_mt_cipher() -> u16 {
    let plaintext = "AAAAAAAAAAAAAA".as_bytes();
    let ciphertext = mt_encryption_oracle(plaintext);

    let padding_len = ciphertext.len() - plaintext.len();
    let padding = vec![0; padding_len];
    let input = [padding, plaintext.to_vec()].concat();

    let range = std::u16::MIN..std::u16::MAX;
    for key in range {
        let guess = mt_cipher_encrypt(key, &input);
        if guess[padding_len..] == ciphertext[padding_len..] {
            return key;
        }
    }

    panic!("key not found!")
}

pub fn mt_encryption_oracle(bytes: &[u8]) -> Vec<u8> {
    let key = 43210;
    let mut input = vec![];

    // prefix random number of random bytes
    for i in 0..SmallRng::seed_from_u64(123456).gen_range(0, 40) {
        input.push(SmallRng::seed_from_u64(i as u64).gen());
    }
    input.append(&mut bytes.to_vec());

    mt_cipher_encrypt(key, &input)
}

fn random_token() -> u32 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    MersenneRng::new(now).extract_number()
}

pub fn detect_timestamp_seeded_token() -> bool {
    guess_unix_timestamp_seed(random_token());
    true
}

// Wait a random number of seconds between 40 and 1000.
// Seeds the RNG with the current Unix timestamp
// Waits a random number of seconds again.
// Returns the first 32 bit output of the RNG.
pub fn timestamp_seeded_rng_oracle() -> (u32, u32) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    // simulate passage of time
    let r = rand::thread_rng().gen_range(80, 2000);
    let seed = now.checked_sub(Duration::from_secs(r)).unwrap().as_secs() as u32;

    // seed with timestamp and return random numbesrs
    let mut rng = MersenneRng::new(seed);
    (rng.extract_number(), seed)
}

pub fn guess_unix_timestamp_seed(first_generated_number: u32) -> u32 {
    let seconds_in_week = 604800;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();

    for i in 0..seconds_in_week {
        let guess = now.checked_sub(Duration::from_secs(i)).unwrap().as_secs() as u32;
        if MersenneRng::new(guess).extract_number() == first_generated_number {
            return guess;
        }
    }

    panic!("seed not found");
}

#[test]
fn mt_stream_cipher() {
    let key = 12345;
    let plaintext = b"This is a test".to_vec();
    assert_eq!(
        plaintext,
        mt_cipher_decrypt(key, &mt_cipher_encrypt(key, &plaintext))
    );
}
