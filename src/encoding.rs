use base64;
use hex;

/// Accepts a hexadecimal encoded set of bytes and coverts them to Base64 format.
pub fn hex_to_base64(input: String) -> Result<String, hex::FromHexError> {
    Ok(base64::encode(&hex::decode(input)?))
}

pub fn pkcs7_encode(bytes: &mut Vec<u8>, size: usize) {
    if size >= 256 {
        panic!("PKCS#7 is only defined for size lesser than 256")
    }

    let num_padding_bytes;
    if bytes.len() == size {
        num_padding_bytes = size;
    } else {
        num_padding_bytes = size - (bytes.len() % size);
    }

    for _i in 0..num_padding_bytes {
        bytes.push(num_padding_bytes.to_be_bytes().last().unwrap().clone());
    }
}

pub fn pkcs7_decode(bytes: &mut Vec<u8>, size: usize) {
    if bytes.len() == 0 || bytes.len() % size != 0 || size == 0 {
        return;
    }
    if bytes.len() < size {
        panic!("cannot decode if length is lesser than final size")
    }
    if size >= 256 {
        panic!("PKCS#7 is only defined for size lesser than 256")
    }

    let num_padding_bytes = *bytes.last().unwrap() as usize;
    let mut prev_byte = bytes.last().unwrap().clone();

    for _i in 0..num_padding_bytes {
        if bytes.last().unwrap() != &prev_byte {
            panic!("invalid pkcs7 encoding");
        }
        prev_byte = bytes.pop().unwrap();
    }
}
