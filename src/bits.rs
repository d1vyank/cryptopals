pub fn invert_right_shift_xor(n: usize, y: u32) -> u32 {
    let mut out = u32_to_bool_vec(y);

    for i in n..32 {
        out[i] ^= out[i - n];
    }

    bool_vec_to_u32(out)
}

pub fn invert_left_shift_and_xor(n: usize, y: u32, c: u32) -> u32 {
    let mut out = u32_to_bool_vec(y);
    let c = u32_to_bool_vec(c);

    for i in (0..(32 - n)).rev() {
        out[i] ^= out[i + n] & c[i];
    }

    bool_vec_to_u32(out)
}

fn u32_to_bool_vec(x: u32) -> Vec<bool> {
    let mut y = vec![];
    for i in (0..32).rev() {
        y.push(is_bit_set(x, i));
    }

    y
}

fn bool_vec_to_u32(y: Vec<bool>) -> u32 {
    let mut x = 0;
    for i in (0..32).rev() {
        if y[31 - i] {
            //set bit i
            x |= 1 << (i);

        } else {
            //unset bit i
            x &= !(1 << (i));
        }
    }
    x
}

fn is_bit_set(input: u32, n: u8) -> bool {
    if n >= 32 {
        panic!("n cannot be > 32");
    }

    input & (1 << n) != 0
}

#[test]
fn u32_bools_conversion() {
    let x = 197696123;
    assert_eq!(x, bool_vec_to_u32(u32_to_bool_vec(x)));
}

#[test]
fn bools_to_u32() {
    let v = vec![true; 32];
    assert_eq!(bool_vec_to_u32(v), std::u32::MAX);

    let mut v = vec![false; 32];
    v[0] = true;
    assert_eq!(bool_vec_to_u32(v), 2147483648);
}

#[test]
fn right_shift_xor_inversion() {
    let x = 4294967295;
    let x_t = x ^ (x >> 11);
    assert_eq!(x, invert_right_shift_xor(11, x_t));
}

#[test]
fn left_shift_and_xor_inversion() {
    let x = 12345678;
    let c = 9876543;
    let x_t = x ^ ((x << 15) & c);

    assert_eq!(x, invert_left_shift_and_xor(15, x_t, c));
}
