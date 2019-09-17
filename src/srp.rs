use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::cast::FromPrimitive;
use num_traits::pow::Pow;
use rand::{self, thread_rng, Rng};

use crate::dh;

pub struct Server {
    salt: u32,
    k: u32,
    I: String,
    P: String,
    v: BigUint,
    public_key: BigUint,
    client_public_key: BigUint,
    secret: dh::Secret,
}

pub struct Client {
    k: u32,
    I: String,
    P: String,
    public_key: BigUint,
    secret: dh::Secret,
}

pub struct SimpleServer {
    salt: u32,
    I: String,
    P: String,
    v: BigUint,
    u: BigUint,
    public_key: BigUint,
    client_public_key: BigUint,
    secret: dh::Secret,
}

pub struct SimpleClient {
    I: String,
    P: String,
    public_key: BigUint,
    secret: dh::Secret,
}

pub struct ZeroKeyClient {
    I: String,
    public_key: BigUint,
}

impl Server {
    pub fn new(k: u32, I: String, P: String) -> Self {
        let salt: u32 = thread_rng().gen();

        let xH = sha256_hash(&[&salt.to_be_bytes(), P.as_bytes()].concat());
        let x = u32::from_be_bytes([xH[0], xH[1], xH[2], xH[3]]) % 256;

        let v = dh::primitive_root().pow(x) % dh::chosen_prime();
        let secret = dh::ephemeral_secret();
        let public_key =
            k * v.clone() + dh::public_key(&dh::chosen_prime(), &dh::primitive_root(), &secret);

        Server {
            salt: salt,
            k: k,
            I: I,
            P: P,
            v: v,
            public_key: public_key,
            client_public_key: Default::default(),
            secret: secret,
        }
    }

    pub fn accept_handshake(
        &mut self,
        client_I: String,
        client_public_key: &BigUint,
    ) -> (u32, BigUint) {
        if self.I != client_I {
            panic!("email doesn't match");
        }

        self.client_public_key = client_public_key.clone();
        (self.salt, self.public_key.clone())
    }

    pub fn complete_handshake(&self, hashed_key: &[u8]) -> bool {
        let uH = sha256_hash(
            &[
                self.client_public_key.to_bytes_be(),
                self.public_key.to_bytes_be(),
            ]
            .concat(),
        );
        let u = u32::from_be_bytes([uH[0], uH[1], uH[2], uH[3]]) % 256;

        let S = (self.client_public_key.clone() * self.v.pow(u))
            .modpow(&self.secret.key.clone(), &dh::chosen_prime());

        let K = sha256_hash(&S.to_bytes_be());

        hmac_sha256(&K, &self.salt.to_be_bytes()) == hashed_key
    }
}

impl Client {
    pub fn new(k: u32, I: String, P: String) -> Self {
        let secret = dh::ephemeral_secret();
        let public_key = dh::public_key(&dh::chosen_prime(), &dh::primitive_root(), &secret);
        Client {
            k: k,
            I: I,
            P: P,
            public_key: public_key,
            secret: secret,
        }
    }

    pub fn initiate_handshake(&self) -> (String, BigUint) {
        (self.I.clone(), self.public_key.clone())
    }

    pub fn complete_handshake(&self, salt: u32, server_public_key: &BigUint) -> Vec<u8> {
        let uH = sha256_hash(
            &[
                self.public_key.to_bytes_be(),
                server_public_key.to_bytes_be(),
            ]
            .concat(),
        );
        let u = u32::from_be_bytes([uH[0], uH[1], uH[2], uH[3]]) % 256;

        let xH = sha256_hash(&[&salt.to_be_bytes(), self.P.as_bytes()].concat());
        let x = u32::from_be_bytes([xH[0], xH[1], xH[2], xH[3]]) % 256;

        let S = (server_public_key - (self.k * dh::primitive_root().pow(x)))
            .modpow(&(self.secret.key.clone() + (u * x)), &dh::chosen_prime());

        let K = sha256_hash(&S.to_bytes_be());
        hmac_sha256(&K, &salt.to_be_bytes())
    }
}

impl ZeroKeyClient {
    pub fn new(public_key: BigUint, I: String) -> Self {
        ZeroKeyClient {
            public_key: public_key,
            I: I,
        }
    }

    pub fn initiate_handshake(&self) -> (String, BigUint) {
        (self.I.clone(), self.public_key.clone())
    }

    pub fn complete_handshake(&self, salt: u32, _server_public_key: &BigUint) -> Vec<u8> {
        let S = BigUint::from_u64(0).unwrap();

        let K = sha256_hash(&S.to_bytes_be());
        hmac_sha256(&K, &salt.to_be_bytes())
    }
}

impl SimpleServer {
    pub fn new(I: String, P: String) -> Self {
        let salt: u32 = thread_rng().gen();

        let xH = sha256_hash(&[&salt.to_be_bytes(), P.as_bytes()].concat());
        let x = u32::from_be_bytes([xH[0], xH[1], xH[2], xH[3]]) % 256;

        let v = dh::primitive_root().pow(x) % dh::chosen_prime();
        let secret = dh::ephemeral_secret();
        let public_key = dh::public_key(&dh::chosen_prime(), &dh::primitive_root(), &secret);

        let low = std::u8::MIN.to_biguint().unwrap();
        let high = std::u8::MAX.to_biguint().unwrap();
        let u = thread_rng().gen_biguint_range(&low, &high);
        SimpleServer {
            salt: salt,
            I: I,
            P: P,
            v: v,
            u: u,
            public_key: public_key,
            client_public_key: Default::default(),
            secret: secret,
        }
    }

    pub fn accept_handshake(
        &mut self,
        client_I: String,
        client_public_key: &BigUint,
    ) -> (u32, BigUint, BigUint) {
        if self.I != client_I {
            panic!("email doesn't match");
        }

        self.client_public_key = client_public_key.clone();
        (self.salt, self.public_key.clone(), self.u.clone())
    }

    pub fn complete_handshake(&self, hashed_key: &[u8]) -> bool {
        let S = (self.client_public_key.clone() * self.v.pow(&self.u))
            .modpow(&self.secret.key.clone(), &dh::chosen_prime());

        let K = sha256_hash(&S.to_bytes_be());

        hmac_sha256(&K, &self.salt.to_be_bytes()) == hashed_key
    }
}

impl SimpleClient {
    pub fn new(I: String, P: String) -> Self {
        let secret = dh::ephemeral_secret();
        let public_key = dh::public_key(&dh::chosen_prime(), &dh::primitive_root(), &secret);
        SimpleClient {
            I: I,
            P: P,
            public_key: public_key,
            secret: secret,
        }
    }

    pub fn initiate_handshake(&self) -> (String, BigUint) {
        (self.I.clone(), self.public_key.clone())
    }

    pub fn complete_handshake(
        &self,
        salt: u32,
        server_public_key: &BigUint,
        u: &BigUint,
    ) -> Vec<u8> {
        let xH = sha256_hash(&[&salt.to_be_bytes(), self.P.as_bytes()].concat());
        let x = u32::from_be_bytes([xH[0], xH[1], xH[2], xH[3]]) % 256;

        let S = server_public_key.modpow(
            &(self.secret.key.clone() + (u * (x as u128))),
            &dh::chosen_prime(),
        );

        let K = sha256_hash(&S.to_bytes_be());
        hmac_sha256(&K, &salt.to_be_bytes())
    }
}

pub fn simple_srp_offline_dict_mitm<'a, I>(c: &SimpleClient, dictionary: I) -> String
where
    I: Iterator<Item = &'a str>,
{
    // Chosen server params
    let salt = 0;
    let b = BigUint::from_u64(1).unwrap();
    let B = dh::primitive_root().modpow(&b, &dh::chosen_prime());
    let u = BigUint::from_u64(1).unwrap();

    let (_, A) = c.initiate_handshake();
    let hashed_key = c.complete_handshake(salt, &B, &u);

    // Perform server-side calculation of the shared key with the guessed password
    for guess in dictionary {
        let xH = sha256_hash(&[&salt.to_be_bytes(), guess.as_bytes()].concat());
        let x = u32::from_be_bytes([xH[0], xH[1], xH[2], xH[3]]) % 256;

        let v = dh::primitive_root().pow(x) % dh::chosen_prime();

        let S = (A.clone() * v.pow(&u)).modpow(&b, &dh::chosen_prime());
        let K = sha256_hash(&S.to_bytes_be());

        if hmac_sha256(&K, &salt.to_be_bytes()) == hashed_key {
            return guess.to_string();
        }
    }

    panic!("password not found in dictionary");
}

fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(input);
    let mut out = vec![0; hasher.output_bytes()];
    hasher.result(&mut out);
    out
}

fn hmac_sha256(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut hasher = Hmac::new(Sha256::new(), key);
    hasher.input(input);
    let mut out = vec![0; hasher.output_bytes()];
    hasher.raw_result(&mut out);
    out
}
