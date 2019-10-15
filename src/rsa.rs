use num_bigint::BigUint;
use num_rational::Ratio;
use num_traits::cast::FromPrimitive;
use num_traits::identities::{One, Zero};
use num_traits::pow::Pow;
use openssl::bn::BigNum;
use rand::Rng;
use std::ops::{Div, Mul};

use crate::encoding;
use crate::math;
use crate::sha1;

pub struct RSA {
    /// (e, n) tuple
    pub public_key: (BigUint, BigUint),
    /// (d, n) tuple
    private_key: (BigUint, BigUint),
}

pub trait ParityOracle {
    fn parity_oracle(&self, ciphertext: &[u8]) -> bool;
}

impl RSA {
    pub fn new(mod_bits: usize) -> Self {
        if mod_bits % 8 != 0 {
            panic!("modulus bit size must be a multiple of 8")
        }
        let p = generate_random_prime(mod_bits / 2);
        let q = generate_random_prime(mod_bits / 2);

        let n = p.clone() * q.clone();

        let et = (p - 1u32) * (q - 1u32);
        let e = BigUint::from_u64(3).unwrap();

        let d = math::invmod(&e, &et);
        RSA {
            public_key: (e, n.clone()),
            private_key: (d, n),
        }
    }

    pub fn public_key(&self) -> (BigUint, BigUint) {
        self.public_key.clone()
    }

    pub fn encrypt(&self, bytes: &[u8]) -> Vec<u8> {
        let num = count_preceeding_zeros(bytes);
        let m = BigUint::from_bytes_be(bytes);
        let mut c = m
            .modpow(&self.public_key.0, &self.public_key.1)
            .to_bytes_be();
        left_pad_zeros(&mut c, num);
        c
    }
    pub fn decrypt(&self, bytes: &[u8]) -> Vec<u8> {
        let num = count_preceeding_zeros(bytes);
        let c = BigUint::from_bytes_be(bytes);
        let mut m = c
            .modpow(&self.private_key.0, &self.private_key.1)
            .to_bytes_be();
        left_pad_zeros(&mut m, num);
        m
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
        if bytes[0] != 0 {
            valid = false;
        }
        if bytes[1] != 1 {
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

    // padding format is 00h 01h ffh ffh ... ffh ffh 00h 32bitLength String+SHA1
    fn pad_to_1024(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        let len = bytes.len() as u32;

        out.push(0);
        out.push(1);
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

impl ParityOracle for RSA {
    fn parity_oracle(&self, ciphertext: &[u8]) -> bool {
        self.decrypt(ciphertext).last().unwrap() & 1 == 0
    }
}

fn generate_random_prime(bits: usize) -> BigUint {
    let mut b = BigNum::new().unwrap();
    b.generate_prime(bits as i32, false, None, None).unwrap();
    BigUint::from_bytes_be(&b.to_vec())
}

fn left_pad_zeros(m: &mut Vec<u8>, num: usize) {
    m.splice(..0, vec![0u8; num].iter().cloned());
}

fn count_preceeding_zeros(m: &[u8]) -> usize {
    let mut count = 0;
    for i in 0..m.len() {
        if m[i] != 0u8 {
            break;
        }
        count += 1;
    }
    count
}

fn pkcs_1dot5_pad(m: &[u8], size: usize) -> Vec<u8> {
    let size = size / 8;
    if size < (m.len() + 3) {
        panic!("message to large")
    }
    let mut r = rand::thread_rng();
    let mut ps = vec![0u8, 2u8];
    for _ in 0..(size - 3 - m.len()) {
        ps.push(r.gen_range(1, 255));
    }
    ps.push(0u8);
    ps.append(&mut m.to_vec());
    ps
}

fn is_pkcs_1dot5_valid(m: &[u8], size: usize) -> bool {
    if m.len() != size / 8 {
        return false;
    }
    if m[0] != 0u8 {
        return false;
    }
    if m[1] != 2u8 {
        return false;
    }

    true
}

pub fn broadcast_attack() -> bool {
    let plaintext = "Big Yellow Submarine";
    let (r1, r2, r3) = (RSA::new(2048), RSA::new(2048), RSA::new(2048));
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

    let c = (c1 * m_s_1.clone() * math::invmod(&m_s_1, &n1))
        + (c2 * m_s_2.clone() * math::invmod(&m_s_2, &n2))
        + (c3 * m_s_3.clone() * math::invmod(&m_s_3, &n3));
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
        VulnerableServer {
            rsa: RSA::new(2048),
        }
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

    (BigUint::from_bytes_be(&p_) * math::invmod(&S, &N) % N).to_bytes_be()
}

pub fn forge_rsa_signature(message: String) -> Vec<u8> {
    let message = message.as_bytes();
    let hash = sha1::hash(&message);
    let len = (message.len() + hash.len()) as u32;
    let padding: Vec<u8> = vec![0, 1, 255, 0];
    let mut out = [padding, len.to_be_bytes().to_vec(), message.to_vec(), hash].concat();

    // fill with garbage, using three gives us something closer to a perfect cube
    for _ in 0..(128 - out.len()) {
        out.push(3);
    }

    let mut cube_root = BigUint::from_bytes_be(&out).nth_root(3).to_bytes_be();
    // replace preceeding zero lost during int conversion
    left_pad_zeros(&mut cube_root, 1);
    cube_root
}

pub fn parity_oracle_attack<O: ParityOracle>(
    ciphertext: &[u8],
    (e, n): (BigUint, BigUint),
    oracle: O,
) -> Vec<u8> {
    let two = BigUint::from_u64(2).unwrap();
    let mut multiple = two.clone().pow(BigUint::from_u64(1500).unwrap());
    let mut upper_bound = n.clone() / multiple.clone();
    let mut lower_bound = BigUint::from_u64(0).unwrap();

    while (upper_bound.clone() - lower_bound.clone()) > BigUint::one() {
        let ciphertext_multiple = BigUint::from_bytes_be(ciphertext) * multiple.modpow(&e, &n);
        let is_plaintext_even = oracle.parity_oracle(&ciphertext_multiple.to_bytes_be());

        let diff = (upper_bound.clone() - lower_bound.clone()) / 2u8;
        if is_plaintext_even {
            // (2^x)th multiple of plaintext doesn't wrap n, so it must be lesser than n/2^x
            upper_bound = upper_bound.clone() - diff;
        } else {
            lower_bound = lower_bound.clone() + diff;
        }
        // println!(
        //     "{:}",
        //     encoding::ascii_encode(&(upper_bound.clone() * 2u32).to_bytes_be())
        // );
        multiple *= 2u8;
    }

    // TODO: Solution converges to plaintext/2 for some reason, so double it
    let upper_bound = upper_bound.clone() * 2u32;
    let lower_bound = lower_bound.clone() * 2u32;

    // figure out which bound has the same parity as the plaintext and return it
    let is_plaintext_even = oracle.parity_oracle(&ciphertext);
    if is_plaintext_even && upper_bound.clone().to_bytes_be().last().unwrap() & 1 == 0 {
        upper_bound.to_bytes_be()
    } else {
        lower_bound.to_bytes_be()
    }
}

pub struct PaddingOracle {
    r: RSA,
    bits: usize,
}

impl PaddingOracle {
    pub fn new(bits: usize) -> Self {
        PaddingOracle {
            r: RSA::new(bits),
            bits: bits,
        }
    }

    pub fn oracle(&self, c: &[u8]) -> bool {
        is_pkcs_1dot5_valid(&self.r.decrypt(c), self.bits)
    }

    pub fn encrypt(&self, m: &[u8]) -> Vec<u8> {
        self.r.encrypt(&pkcs_1dot5_pad(m, self.bits))
    }

    pub fn public_key(&self) -> (BigUint, BigUint) {
        self.r.public_key.clone()
    }
}

pub fn pkcs_padding_oracle_attack(bits: usize) {
    let msg = "Big Yellow Submarine";
    let b = BigUint::from(2u8).pow(bits as u32 - 16u32);

    let oracle = PaddingOracle::new(bits);
    let (e, n) = oracle.public_key();
    let c = oracle.encrypt(msg.as_bytes());
    let mut ranges = vec![];

    if !oracle.oracle(&c) {
        panic!("invalid ciphertext");
    }

    let find_pkcs_conforming_multiple = |c: &[u8], s_init: &BigUint, s_limit: &BigUint| {
        let mut s = s_init.clone();

        loop {
            if &s > s_limit && s_limit != &BigUint::zero() {
                return None;
            }

            let mut multiple =
                ((BigUint::from_bytes_be(c) * s.modpow(&e, &n)) % n.clone()).to_bytes_be();

            left_pad_zeros(&mut multiple, count_preceeding_zeros(c));
            if oracle.oracle(&multiple) {
                return Some(s);
            }
            s += BigUint::one();
        }
    };

    let find_ranges = |s: BigUint, ranges: &[(Ratio<BigUint>, Ratio<BigUint>)]| {
        let mut new_ranges = vec![];
        for (lower, upper) in ranges {
            // as - 3B +1 / n
            let mut r = ((lower.mul(s.clone()) - b.clone().mul(3u8) + BigUint::one()) / n.clone())
                .ceil()
                .to_integer();
            // bs - 2B / n
            let r_max = ((upper.mul(s.clone()) - b.clone().mul(2u8)) / n.clone())
                .ceil()
                .to_integer();
            while r < r_max {
                let mut new_lower =
                    Ratio::from(2u32 * b.clone() + r.clone() * n.clone()) / s.clone();
                let mut new_upper =
                    Ratio::from(3u32 * b.clone() - 1u32 + r.clone() * n.clone()) / s.clone();

                if &new_lower.ceil() < lower {
                    new_lower = lower.clone();
                }
                if &new_upper.floor() > upper {
                    new_upper = upper.clone();
                }
                new_ranges.push((new_lower.ceil(), new_upper.floor()));
                r += 1u32;
            }
        }
        new_ranges
    };

    // initial constraints
    let mut lower = Ratio::from(b.clone().mul(2u8));
    let mut upper = Ratio::from(b.clone().mul(3u8) - 1u8);

    let mut i = 1;
    let mut s = BigUint::zero();
    while lower != upper {
        if i == 1 {
            let s_init = Ratio::from(n.clone().div(b.clone().mul(3u8)))
                .ceil()
                .to_integer();
            s = find_pkcs_conforming_multiple(&c, &s_init, &BigUint::zero()).unwrap();
        } else {
            // 2 * (bs - 2B)/n
            let mut r = 2u8
                * ((upper.clone().mul(s.clone()) - b.clone().mul(2u8)).div(n.clone()))
                    .ceil()
                    .to_integer();
            s = loop {
                let s_lower =
                    Ratio::from(b.clone().mul(2u8) + r.clone().mul(n.clone())) / upper.clone();
                let s_upper =
                    Ratio::from(b.clone().mul(3u8) + r.clone().mul(n.clone())) / lower.clone();

                match find_pkcs_conforming_multiple(
                    &c,
                    &s_lower.ceil().to_integer(),
                    &s_upper.ceil().to_integer(),
                ) {
                    Some(s) => break s,
                    None => {
                        r += 1u32;
                        continue;
                    }
                };
            };
        }

        ranges = find_ranges(s.clone(), &vec![(lower.clone(), upper.clone())]);
        while ranges.len() != 1 {
            s += 1u32;
            s = find_pkcs_conforming_multiple(&c, &s, &BigUint::zero()).unwrap();
            ranges = find_ranges(s.clone(), &ranges);
        }

        lower = ranges[0].0.clone();
        upper = ranges[0].1.clone();

        i += 1;
    }
    println!(
        "message is {:}",
        encoding::ascii_encode(&ranges[0].1.to_integer().to_bytes_be())
    );
}

#[test]
fn pkcs1dot5_padding() {
    let msg = "Hello, World";
    let m = pkcs_1dot5_pad(msg.as_bytes(), 256);
    assert!(is_pkcs_1dot5_valid(&m, 256));
}

#[test]
fn padding_oracle() {
    let msg = "Hello, World";
    let oracle = PaddingOracle::new(256);
    let c = oracle.encrypt(msg.as_bytes());
    assert!(oracle.oracle(&c))
}
// #[bench]
// fn bench_mod_pow(b: &mut test::Bencher) {
//     let c = b"2436243155349165985002611709542821372890834464272587126782810070973263608310543040337686933353232931169874146578463464911688926714019482018993229371832658228077275028556803821763892665674715568662126403992471290814719704730681127477706054025447689339783355051531671567480914137348635576845674792218621451864253690000080074912501107400788219327139173926420311110211505218314260331614083630143286577348097674379144954725027819544829681076845892232015885886939142357066738720423018750314264105428637349518359690361153393795192466333475839814784548634312979646931045638734399535938602049918931414719684558672973724579243400375129022640600328451657315723154940663184488823886195068305455214285417135847859926063796520578902525035686565200846838566124671080320219819544480365418838142865508672648057259822906636443161146762673874576290524790816446794632258499777731971617516750703203022731177272644473432167476277020895870912287615347642258150455045376641619989580782625866605596773975265966194010911047074870379026846088959827151031853728765125174024773366032008560152436604055216934628831888773802116813";
//     let d = b"14095548085589204533352657183856667160365345684621683948820502442741893128756649313691961000844482116128784693868569308596303343962015365500959897263628322189582453873501340030283793453964792023067358783089904358074504282270132748547963574672859014171705153868663923924972035758605274628852484301689176006527210267001119203332902485358345429486214438267021536403499525957773906636160360543693879149061374815528443535671188958254058170198677999218472592839900425827528877470464690204171576342469396424005809562881244642656067867268963049658155398886720811860375025205503616075584968404254993560235394081454783893137355";
//     let n =
//     b"21143322128383806800028985775785000740548018526932525923230753664112839693134973970537941501266723174193177040802853962894455015943023048251439845895442483284373680810252010045425690180947188034601038174634856537111756423405199122821945362009288521257557730802995885887458053637907911943278726452533764009791106853840283870600008158671493083461128287664462131588501865420925885283322031108226338493613392700044721255161102829701314552361486661035394266712404804567483949869286307849039622633969103681691544122959527106552279887765812117855164815574666410621881995001729907822373415930485136454515603476548797539009931";
//
//     let c = BigUint::parse_bytes(c, 10).unwrap();
//     let d = BigUint::parse_bytes(d, 10).unwrap();
//     let n = BigUint::parse_bytes(n, 10).unwrap();
//
//     b.iter(|| c.modpow(&d, &n));
// }
//
// #[bench]
// fn bench_mod_pow_ramp(b: &mut test::Bencher) {
//     use ramp::int::Int;
//     use std::str::FromStr;
//
//     let c = Int::from_str("2436243155349165985002611709542821372890834464272587126782810070973263608310543040337686933353232931169874146578463464911688926714019482018993229371832658228077275028556803821763892665674715568662126403992471290814719704730681127477706054025447689339783355051531671567480914137348635576845674792218621451864253690000080074912501107400788219327139173926420311110211505218314260331614083630143286577348097674379144954725027819544829681076845892232015885886939142357066738720423018750314264105428637349518359690361153393795192466333475839814784548634312979646931045638734399535938602049918931414719684558672973724579243400375129022640600328451657315723154940663184488823886195068305455214285417135847859926063796520578902525035686565200846838566124671080320219819544480365418838142865508672648057259822906636443161146762673874576290524790816446794632258499777731971617516750703203022731177272644473432167476277020895870912287615347642258150455045376641619989580782625866605596773975265966194010911047074870379026846088959827151031853728765125174024773366032008560152436604055216934628831888773802116813").unwrap();
//     let d =
//     Int::from_str("14095548085589204533352657183856667160365345684621683948820502442741893128756649313691961000844482116128784693868569308596303343962015365500959897263628322189582453873501340030283793453964792023067358783089904358074504282270132748547963574672859014171705153868663923924972035758605274628852484301689176006527210267001119203332902485358345429486214438267021536403499525957773906636160360543693879149061374815528443535671188958254058170198677999218472592839900425827528877470464690204171576342469396424005809562881244642656067867268963049658155398886720811860375025205503616075584968404254993560235394081454783893137355").unwrap();
//     let n =
//     Int::from_str("21143322128383806800028985775785000740548018526932525923230753664112839693134973970537941501266723174193177040802853962894455015943023048251439845895442483284373680810252010045425690180947188034601038174634856537111756423405199122821945362009288521257557730802995885887458053637907911943278726452533764009791106853840283870600008158671493083461128287664462131588501865420925885283322031108226338493613392700044721255161102829701314552361486661035394266712404804567483949869286307849039622633969103681691544122959527106552279887765812117855164815574666410621881995001729907822373415930485136454515603476548797539009931").unwrap();
//
//     b.iter(|| c.pow_mod(&d, &n));
// }
