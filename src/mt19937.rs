// Create a length N array to store the state of the generator
// int[0..N-1] MTs
// int index := N+1


use rand::{thread_rng, Rng};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;
const R: u32 = 31;
const A: u32 = 0x9908B0DF;
const F: u32 = 1812433253;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;

pub struct MersenneRng {
    index: usize,
    mt: Vec<u32>,

}

impl MersenneRng {
    // Initialize the generator from a seed
    pub fn new(seed: u32) -> Self {
        println!("seeding with {:?}", seed);

        let mut mt = vec![seed];
        for i in 1..=(N - 1) {
            let val: u64 = (F as u64) * (mt[i - 1] ^ (mt[i - 1] >> (W - 2))) as u64 + (i as u64);
            mt.push(val as u32);
        }
        MersenneRng { index: N, mt: mt }
    }

    // Extract a tempered value based on MT[index]
    // calling twist() every N numbers
    pub fn extract_number(&mut self) -> u32 {
        if self.index > N {
            panic!("Generator was never seeded");
        }
        if self.index == N {
            self.twist();
        }

        let mut y = self.mt[self.index];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        self.index += 1;

        return y;
    }

    // Generate the next N values from the series x_i
    fn twist(&mut self) {
        for i in 0..(N - 1) {
            let x = (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if (x % 2) != 0 {
                // lowest bit of x is 1
                x_a = x_a ^ A;
            }
            self.mt[i] = self.mt[(i + M) % N] ^ x_a;
        }
        self.index = 0;
    }
}

// Write a routine that performs the following operation:
//

// You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.
//
// From the 32 bit RNG output, discover the seed.

// Wait a random number of seconds between 40 and 1000.
// Seeds the RNG with the current Unix timestamp
// Waits a random number of seconds again.
// Returns the first 32 bit output of the RNG.
pub fn timestamp_seeded_rng_oracle() -> (u32, u32) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // simulate passage of time
    let r = rand::thread_rng().gen_range(80, 2000);
    let seed = now.checked_sub(Duration::from_secs(r)).unwrap().as_secs() as u32;

    // seed with timestamp and return random numbesrs
    let mut rng = MersenneRng::new(seed);
    (rng.extract_number(), seed)
}

pub fn guess_unix_timestamp_seed(first_generated_number: u32) -> u32 {
    let seconds_in_week = 604800;

    for i in 0..seconds_in_week {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let guess = now.checked_sub(Duration::from_secs(i)).unwrap().as_secs() as u32;
        let mut rng = MersenneRng::new(guess);
        let rn = rng.extract_number();
        if rn == first_generated_number {
            return guess;
        }
    }

    panic!("seed not found");
}
