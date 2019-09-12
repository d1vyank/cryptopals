use num_bigint::{BigInt, BigUint, RandBigInt, Sign, ToBigInt, ToBigUint};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use num_traits::identities::{One, Zero};
use openssl::bn::BigNum;
use rand::{self, thread_rng, Rng};

use crate::encoding;
use crate::sha1;

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

    pub fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        let hashed_bytes = sha1::hash(bytes);
        let out = [bytes, &hashed_bytes].concat();
        let out = self.pad_to_1024(&out);
        // sign with private key
        self.decrypt(&out)
    }

    pub fn verify(&self, bytes: &[u8]) -> Vec<u8> {
        // decrypt signature with public key
        let bytes = self.encrypt(bytes);
        let bytes = self.bad_parse(&bytes);
        let hash = sha1::hash(&bytes[0..bytes.len() - 20]);
        if hash != &bytes[bytes.len() - 20..] {
            panic!("verification failed");
        }

        bytes[0..bytes.len() - 20].to_vec()
    }

    fn bad_parse(&self, bytes: &[u8]) -> Vec<u8> {
        let mut valid = true;
        if bytes[0] != 1 {
            valid = false;
        }
        if bytes[1] != 0 {
            valid = false;
        }
        let mut index = 2;
        loop {
            if bytes[index] != std::u8::MAX {
                break;
            }
            index += 1;
        }
        if bytes[index] != 0 {
            valid = false;
        }
        index += 1;

        let len = u32::from_be_bytes([
            bytes[index],
            bytes[index + 1],
            bytes[index + 2],
            bytes[index + 3],
        ]) as usize;
        index += 4;
        if !valid {
            panic!("bad padding");
        }

        bytes[index..index + len].to_vec()
    }

    // padding format is 01h 00h ffh ffh ... ffh ffh 00h 32bitLength String+SHA1
    fn pad_to_1024(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        let len = bytes.len() as u32;

        out.push(1);
        out.push(0);
        // 7 comes from the 0 and 1 in the beginning, the 0 byte at the end, plus four for the length
        for _ in 0..(128 - 7 - len) {
            out.push(std::u8::MAX);
        }
        out.push(0);
        out.append(&mut len.to_be_bytes().to_vec());
        out.append(&mut bytes.to_vec());
        out
    }
}

fn generate_random_prime() -> BigUint {
    let mut b = BigNum::new().unwrap();
    b.generate_prime(1024, false, None, None).unwrap();
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

pub struct VulnerableServer {
    rsa: RSA,
}

impl VulnerableServer {
    pub fn new() -> Self {
        VulnerableServer { rsa: RSA::new() }
    }
    pub fn unpadded_msg_oracle(&self, msg: &[u8]) -> Vec<u8> {
        self.rsa.decrypt(msg)
    }
    pub fn public_key(&self) -> (BigUint, BigUint) {
        self.rsa.public_key()
    }
}

pub fn recover_unpadded_message(server: VulnerableServer, c: &[u8]) -> Vec<u8> {
    let c = BigUint::from_bytes_be(c);
    let (e, N) = server.public_key();

    let S = BigUint::from_u64(2).unwrap();

    let c_ = (S.modpow(&e, &N.clone()) * c) % N.clone();
    let p_ = server.unpadded_msg_oracle(&c_.to_bytes_be());

    (BigUint::from_bytes_be(&p_) * invmod(&S, &N) % N).to_bytes_be()
}

pub fn forge_rsa_signature(message: String) -> Vec<u8> {
    let message = message.as_bytes();
    let hash = sha1::hash(&message);
    let len = (message.len() + hash.len()) as u32;
    let padding: Vec<u8> = vec![1, 0, 255, 0];
    let mut out = [padding, len.to_be_bytes().to_vec(), message.to_vec(), hash].concat();
    // fill with garbage, using three gives us something closer to a perfect cube
    for _ in 0..(128 - out.len()) {
        out.push(3);
    }

    BigUint::from_bytes_be(&out).nth_root(3).to_bytes_be()
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
