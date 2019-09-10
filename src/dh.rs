use crate::aes128;
use crate::encoding;
use crate::sha1;

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use rand::{self, thread_rng, Rng};

pub struct Secret {
    pub key: BigUint,
}

impl Secret {
    pub fn diffie_hellman(&self, public_key: &BigUint) -> BigUint {
        public_key.modpow(&self.key, &chosen_prime())
    }
}

pub fn public_key(p: &BigUint, g: &BigUint, chosen_secret: &Secret) -> BigUint {
    g.modpow(&chosen_secret.key, p)
}

pub fn ephemeral_secret() -> Secret {
    let low = std::u8::MIN.to_biguint().unwrap();
    let high = std::u8::MAX.to_biguint().unwrap();
    Secret {
        key: thread_rng().gen_biguint_range(&low, &high),
    }
}

pub fn chosen_prime() -> BigUint {
    BigUint::from_bytes_be(&hex::decode("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").unwrap())
}

pub fn primitive_root() -> BigUint {
    BigUint::from_bytes_be(b"2")
}

pub struct DhAesCbcConnection {
    handshake_complete: bool,
    ephemeral_secret: Secret,
    public_key: BigUint,
    private_key: Vec<u8>,
    p: BigUint,
    g: BigUint,
}

impl DhAesCbcConnection {
    pub fn new(p: &BigUint, g: &BigUint) -> Self {
        let secret = ephemeral_secret();
        let pk = public_key(p, g, &secret);
        DhAesCbcConnection {
            handshake_complete: false,
            ephemeral_secret: secret,
            public_key: pk,
            private_key: vec![],
            p: p.clone(),
            g: g.clone(),
        }
    }

    pub fn initiate_handshake(&self) -> BigUint {
        self.public_key.clone()
    }

    pub fn accept_handshake(&mut self, public_key: &BigUint) -> BigUint {
        self.complete_handshake(public_key);
        self.public_key.clone()
    }

    pub fn complete_handshake(&mut self, public_key: &BigUint) {
        self.private_key = sha1::hash(
            &self
                .ephemeral_secret
                .diffie_hellman(&public_key)
                .to_bytes_be(),
        )[0..16]
            .to_vec();
        self.handshake_complete = true;
    }

    pub fn encrypt_message(&self, plaintext: String) -> Vec<u8> {
        if !self.handshake_complete {
            panic!("handshake not completed");
        }
        let iv: [u8; 16] = thread_rng().gen();
        let ciphertext =
            aes128::cbc::encrypt(plaintext.as_bytes(), &self.private_key, &iv).unwrap();

        [ciphertext, iv.to_vec()].concat()
    }

    pub fn decrypt_message(&self, ciphertext: Vec<u8>) -> String {
        if !self.handshake_complete {
            panic!("handshake not completed");
        }

        if ciphertext.len() < 32 {
            panic!("invalid message");
        }
        let mut ciphertext = ciphertext;
        let iv = ciphertext.split_off(ciphertext.len() - 16);
        encoding::ascii_encode(&aes128::cbc::decrypt(&ciphertext, &self.private_key, &iv).unwrap())
    }
}

pub mod mitm {
    use super::*;

    pub fn malicious_public_key() {
        let eve_public_key = chosen_prime();
        let message_to_b = "Hello, B".to_string();

        let mut a_conn = DhAesCbcConnection::new(&chosen_prime(), &primitive_root());
        let mut b_conn = DhAesCbcConnection::new(&chosen_prime(), &primitive_root());

        let _a_public_key = a_conn.initiate_handshake();
        let _b_public_key = b_conn.accept_handshake(&eve_public_key);
        a_conn.complete_handshake(&eve_public_key);

        let ciphertext = a_conn.encrypt_message(message_to_b.clone());

        // we can decrypt ciphertext encrypted with shared secret derived from chosen public key
        // shared secret is 0 becuase p ^ (ephemeral_secret) % p = 0
        let key = &sha1::hash(&[0])[0..16];
        let plaintext = aes128::cbc::decrypt(
            &ciphertext[0..ciphertext.len() - 16],
            key,
            &ciphertext[ciphertext.len() - 16..],
        )
        .unwrap();
        assert_eq!(message_to_b, encoding::ascii_encode(&plaintext));
    }

    pub fn malicious_primitive_root() {
        let message_to_b = "Hello, B".to_string();

        // With g = 1
        // public key = g ^ secret % p = 1
        // shared secret = pk ^ secret % p = 1
        let mut a_conn = DhAesCbcConnection::new(&chosen_prime(), &BigUint::from_bytes_be(&[1]));
        let mut b_conn = DhAesCbcConnection::new(&chosen_prime(), &BigUint::from_bytes_be(&[1]));

        let a_public_key = a_conn.initiate_handshake();
        let b_public_key = b_conn.accept_handshake(&a_public_key);
        a_conn.complete_handshake(&b_public_key);

        let ciphertext = a_conn.encrypt_message(message_to_b.clone());
        let key = &sha1::hash(&[1])[0..16];
        let plaintext = aes128::cbc::decrypt(
            &ciphertext[0..ciphertext.len() - 16],
            key,
            &ciphertext[ciphertext.len() - 16..],
        )
        .unwrap();
        assert_eq!(message_to_b, encoding::ascii_encode(&plaintext));

        // With g = p
        // public key = g ^ secret % p = 0
        // shared secret = pk ^ secret % p = 0
        let mut a_conn = DhAesCbcConnection::new(&chosen_prime(), &chosen_prime());
        let mut b_conn = DhAesCbcConnection::new(&chosen_prime(), &chosen_prime());

        let a_public_key = a_conn.initiate_handshake();
        let b_public_key = b_conn.accept_handshake(&a_public_key);
        a_conn.complete_handshake(&b_public_key);

        let ciphertext = a_conn.encrypt_message(message_to_b.clone());
        let key = &sha1::hash(&[0])[0..16];
        let plaintext = aes128::cbc::decrypt(
            &ciphertext[0..ciphertext.len() - 16],
            key,
            &ciphertext[ciphertext.len() - 16..],
        )
        .unwrap();
        assert_eq!(message_to_b, encoding::ascii_encode(&plaintext));

        // With g = p - 1
        // public key = g ^ secret % p = p - 1 (if secret is even) 1 (if secret is odd)
        // shared secret = pk ^ secret % p = p - 1 (if secret is even) 1 (if secret is odd)
        let g = chosen_prime() - 1u8;

        let mut a_conn = DhAesCbcConnection::new(&chosen_prime(), &g);
        let mut b_conn = DhAesCbcConnection::new(&chosen_prime(), &g);

        let a_public_key = a_conn.initiate_handshake();
        let b_public_key = b_conn.accept_handshake(&a_public_key);
        a_conn.complete_handshake(&b_public_key);
        let ciphertext = a_conn.encrypt_message(message_to_b.clone());

        // try with secret = p-1
        let key = &sha1::hash(&g.to_bytes_be())[0..16];
        let plaintext = aes128::cbc::decrypt_pad(
            &ciphertext[0..ciphertext.len() - 16],
            key,
            &ciphertext[ciphertext.len() - 16..],
            true,
        )
        .unwrap();

        if encoding::ascii_encode(&plaintext).contains(&message_to_b) {
            return;
        }

        // if plaintext not founsd, try with secret = 1
        let key = &sha1::hash(&[1])[0..16];
        let plaintext = aes128::cbc::decrypt(
            &ciphertext[0..ciphertext.len() - 16],
            key,
            &ciphertext[ciphertext.len() - 16..],
        )
        .unwrap();

        assert_eq!(message_to_b, encoding::ascii_encode(&plaintext));
    }
}
