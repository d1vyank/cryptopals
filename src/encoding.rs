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

    let mut num_padding_bytes = *bytes.last().unwrap() as usize;
    // Check if last 'size' bytes are filled with the 'size' byte
    if bytes.len() > size {
        let mut last_size_bytes_equal = false;
        for i in bytes.len() - 1..=bytes.len() - size {
            if bytes[i] != bytes[i - 1] && bytes[i] == *size.to_be_bytes().last().unwrap() {
                last_size_bytes_equal = true;
            } else {
                last_size_bytes_equal = false;
            }
        }
        if last_size_bytes_equal {
            num_padding_bytes = size;
        }
    }
    for _i in 0..num_padding_bytes {
        bytes.pop();
    }
}
