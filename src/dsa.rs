use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_traits::identities::{One, Zero};
use rand::{self, thread_rng};

use crate::math;
use crate::sha1;

pub struct DSA {
    pub public_key: BigUint,
    private_key: BigUint,
}

impl DSA {
    pub fn new() -> Self {
        let x = thread_rng().gen_biguint_range(&BigUint::one(), &q());
        let y = g().modpow(&x, &p());
        DSA {
            public_key: y,
            private_key: x,
        }
    }

    pub fn new_verifier(public_key: BigUint) -> Self {
        DSA {
            public_key: public_key,
            private_key: BigUint::zero(),
        }
    }

    pub fn sign(&self, m: &[u8]) -> (BigUint, BigUint) {
        let mut r = BigUint::zero();
        let mut s = BigUint::zero();

        let H_m = BigUint::from_bytes_be(&sha1::hash(m));

        while r == BigUint::zero() || s == BigUint::zero() {
            let k = thread_rng().gen_biguint_range(&BigUint::one(), &q());
            r = g().modpow(&k, &p()) % q();
            s = ((H_m.clone() + self.private_key.clone() * r.clone()) * math::invmod(&k, &q()))
                % q();
        }
        (r, s)
    }

    pub fn verify(&self, m: &[u8], (r, s): (BigUint, BigUint)) -> bool {
        assert!(r > BigUint::zero() && r < q());
        assert!(s > BigUint::zero() && s < q());

        let H_m = BigUint::from_bytes_be(&sha1::hash(m));
        let w = math::invmod(&s, &q());
        let u1 = (H_m * w.clone()) % q();
        let u2 = (r.clone() * w) % q();
        let v = ((g().modpow(&u1, &p()) * self.public_key.clone().modpow(&u2, &p())) % p()) % q();

        v == r
    }
}

pub fn recover_private_key_weak_nonce(
    message: String,
    (r, s): (BigInt, BigInt),
    pub_key: BigInt,
) -> BigInt {
    let q_ = BigInt::from(q());
    let g_ = BigInt::from(g());
    let p_ = BigInt::from(p());

    let H_m = BigInt::from_bytes_be(Sign::Plus, &sha1::hash(message.as_bytes()));
    let r_inv = BigInt::from(math::invmod(
        &BigUint::from_bytes_be(&r.to_bytes_be().1),
        &q(),
    ));
    for k_guess in 0..std::u16::MAX {
        // q is added to workaround the fact that BigUint does not provide euclidean modulus
        let x: BigInt = ((((s.clone() * k_guess) % q_.clone()) - H_m.clone()) * r_inv.clone()
            % q_.clone())
            + q_.clone();
        if g_.modpow(&x, &p_) == pub_key {
            return x;
        }
    }

    panic!("key not found");
}

fn p() -> BigUint {
    BigUint::from_bytes_be(&hex::decode("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1").unwrap())
}

fn q() -> BigUint {
    BigUint::from_bytes_be(&hex::decode("f4f47f05794b256174bba6e9b396a7707e563c5b").unwrap())
}

fn g() -> BigUint {
    BigUint::from_bytes_be(&hex::decode("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291").unwrap())
}

#[test]
fn dsa() {
    let message = "BIG YELLOW SUBMARINE";
    let d = DSA::new();

    let signature = d.sign(message.as_bytes());
    assert!(d.verify(message.as_bytes(), signature))
}
