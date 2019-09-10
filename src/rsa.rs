use num_bigint::ToBigInt;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use num_traits::identities::{One, Zero};
use openssl::bn::BigNum;

use crate::encoding;

pub struct RSA {
    /// (e, n) tuple
    pub public_key: (BigUint, BigUint),
    /// (d, n) tuple
    private_key: (BigUint, BigUint),
}

impl RSA {
    pub fn new() -> Self {
        let p = generate_random_prime();
        let q = generate_random_prime();
        let n = p.clone() * q.clone();

        let et = (p - 1u32) * (q - 1u32);
        let e = BigUint::from_u64(3).unwrap();

        let d = invmod(&e, &et);

        RSA {
            public_key: (e, n.clone()),
            private_key: (d, n),
        }
    }

    pub fn public_key(&self) -> (BigUint, BigUint) {
        self.public_key.clone()
    }

    pub fn encrypt(&self, bytes: &[u8]) -> Vec<u8> {
        let m = BigUint::from_bytes_be(bytes);
        m.modpow(&self.public_key.0, &self.public_key.1)
            .to_bytes_be()
    }
    pub fn decrypt(&self, bytes: &[u8]) -> Vec<u8> {
        let c = BigUint::from_bytes_be(bytes);
        c.modpow(&self.private_key.0, &self.private_key.1)
            .to_bytes_be()
    }
}

fn generate_random_prime() -> BigUint {
    let mut b = BigNum::new().unwrap();
    b.generate_prime(512, false, None, None).unwrap();
    BigUint::from_bytes_be(&b.to_vec())
}

fn invmod(a0: &BigUint, m0: &BigUint) -> BigUint {
    let (a0, m0) = (a0.to_bigint().unwrap(), m0.to_bigint().unwrap());

    if m0 == BigInt::one() {
        return BigUint::one();
    }
    let (mut a, mut m, mut x0, mut inv) = (
        a0.clone(),
        m0.clone(),
        BigInt::from_u64(0).unwrap(),
        BigInt::from_u64(1).unwrap(),
    );
    while a > BigInt::one() {
        inv -= (a.clone() / m.clone()) * x0.clone();
        a = a.clone() % m.clone();
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x0, &mut inv);
    }

    if inv < BigInt::zero() {
        inv += m0.clone()
    }

    inv.to_biguint().unwrap()
}

pub fn broadcast_attack() -> bool {
    let plaintext = "Big Yellow Submarine";
    let (r1, r2, r3) = (RSA::new(), RSA::new(), RSA::new());
    let (c1, c2, c3) = (
        r1.encrypt(plaintext.as_bytes()),
        r2.encrypt(plaintext.as_bytes()),
        r3.encrypt(plaintext.as_bytes()),
    );
    let ((_, n1), (_, n2), (_, n3)) = (r1.public_key(), r2.public_key(), r3.public_key());

    let c1 = BigUint::from_bytes_be(&c1);
    let c2 = BigUint::from_bytes_be(&c2);
    let c3 = BigUint::from_bytes_be(&c3);

    let m_s_1 = n2.clone() * n3.clone();
    let m_s_2 = n1.clone() * n3.clone();
    let m_s_3 = n1.clone() * n2.clone();
    let n_123 = n1.clone() * n2.clone() * n3.clone();

    let c = (c1 * m_s_1.clone() * invmod(&m_s_1, &n1))
        + (c2 * m_s_2.clone() * invmod(&m_s_2, &n2))
        + (c3 * m_s_3.clone() * invmod(&m_s_3, &n3));
    let c = c % n_123;

    let decrypted = encoding::ascii_encode(&c.nth_root(3).to_bytes_be());

    assert_eq!(decrypted, plaintext);
    true
}

#[test]
fn inverse_modulus() {
    assert_eq!(
        BigUint::from_u64(1969).unwrap(),
        invmod(
            &BigUint::from_u64(42).unwrap(),
            &BigUint::from_u64(2017).unwrap()
        )
    );
    assert_eq!(
        BigUint::from_u64(2753).unwrap(),
        invmod(
            &BigUint::from_u64(17).unwrap(),
            &BigUint::from_u64(3120).unwrap()
        )
    );
}
