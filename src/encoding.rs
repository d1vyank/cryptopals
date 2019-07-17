use base64;
use hex;

/// Accepts a hexadecimal encoded set of bytes and coverts them to Base64 format.
pub fn hex_to_base64(input: String) -> Result<String, hex::FromHexError> {
    Ok(base64::encode(&hex::decode(input)?))
}

pub fn pkcs7_padded(mut bytes: Vec<u8>, size: usize) -> Vec<u8> {
    if bytes.len() > size {
        panic!("cannot pad if final size if lesser than length")
    }
    if size >= 256 {
        panic!("PKCS#7 is only defined for size lesser than 256")
    }
    if bytes.len() == size {
        return bytes;
    }

    let num_padding_bytes = size - bytes.len();
    for _i in 0..num_padding_bytes {
        bytes.push(num_padding_bytes.to_be_bytes().last().unwrap().clone());
    }

    bytes
}
