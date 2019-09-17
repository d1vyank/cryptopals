use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::cast::FromPrimitive;
use num_traits::identities::{One, Zero};

pub fn invmod(a0: &BigUint, m0: &BigUint) -> BigUint {
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
