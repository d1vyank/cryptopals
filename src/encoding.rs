use base64;
use hex;

use std::error;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct PKCS7DecodeError;

impl fmt::Display for PKCS7DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid PKCS7 encoded input")
    }
}

impl error::Error for PKCS7DecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

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

pub fn pkcs7_decode(bytes: &[u8], size: usize) -> Result<Vec<u8>, PKCS7DecodeError> {
    if bytes.len() == 0 || bytes.len() % size != 0 || size == 0 {
        return Err(PKCS7DecodeError {});
    }
    if *bytes.last().unwrap() as usize == 0 {
        return Err(PKCS7DecodeError {});
    }
    if bytes.len() < size {
        panic!("cannot decode if length is lesser than final size")
    }
    if size >= 256 {
        panic!("PKCS#7 is only defined for size lesser than 256")
    }
    let mut output = bytes.to_vec();

    let num_padding_bytes = *output.last().unwrap() as usize;
    let mut prev_byte = output.last().unwrap().clone();

    for _i in 0..num_padding_bytes {
        if output.last().unwrap() != &prev_byte {
            return Err(PKCS7DecodeError {});
        }
        prev_byte = output.pop().unwrap();
    }

    Ok(output)
}
