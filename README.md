My solutions to the [Matasano Crypto Challenges](https://cryptopals.com/)

# Execute

```Bash
$ cargo test
```

# Progress

## Set 1: Basics

- [x] Challenge 1: Convert hex to base64
- [x] Challenge 2: Fixed XOR
- [x] Challenge 3: Single-byte XOR cipher
- [x] Challenge 4: Detect single-character XOR
- [x] Challenge 5: Implement repeating-key XOR
- [x] Challenge 6: Break repeating-key XOR
- [x] Challenge 7: AES in ECB mode
- [x] Challenge 8: Detect AES in ECB mode

## Set 2: Block crypto

- [x] Challenge 9: Implement PKCS#7 padding
- [x] Challenge 10: Implement CBC mode
- [x] Challenge 11: An ECB/CBC detection oracle
- [x] Challenge 12: Byte-at-a-time ECB decryption (Simple)
- [x] Challenge 13: ECB cut-and-paste
- [x] Challenge 14: Byte-at-a-time ECB decryption (Harder)
- [x] Challenge 15: PKCS#7 padding validation
- [x] Challenge 16: CBC bitflipping attacks

## Set 3: Block & stream crypto

- [x] Challenge 17: The CBC padding oracle
- [x] Challenge 18: Implement CTR, the stream cipher mode
- [x] Challenge 19: Break fixed-nonce CTR mode using substitutions
- [x] Challenge 20: Break fixed-nonce CTR statistically
- [x] Challenge 21: Implement the MT19937 Mersenne Twister RNG
- [x] Challenge 22: Crack an MT19937 seed
- [x] Challenge 23: Clone an MT19937 RNG from its output
- [x] Challenge 24: Create the MT19937 stream cipher and break it

## Set 4: Stream crypto and randomness

- [x] Challenge 25: Break "random access read/write" AES CTR
- [x] Challenge 26: CTR bitflipping
- [x] Challenge 27: Recover the key from CBC with IV=Key
- [x] Challenge 28: Implement a SHA-1 keyed MAC
- [x] Challenge 29: Break a SHA-1 keyed MAC using length extension
- [ ] Challenge 30: Break an MD4 keyed MAC using length extension
- [x] Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak
- [x] Challenge 32: Break HMAC-SHA1 with a slightly less artificial timing leak


## Set 5: Diffie-Hellman and friends

- [x] Challenge 33: Implement Diffie-Hellman
- [x] Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
- [x] Challenge 35: Implement DH with negotiated groups, and break with malicious "g" parameters
- [x] Challenge 36: Implement Secure Remote Password (SRP)
- [x] Challenge 37: Break SRP with a zero key
- [x] Challenge 38: Offline dictionary attack on simplified SRP
- [x] Challenge 39: Implement RSA
- [x] Challenge 40: Implement an E=3 RSA Broadcast attack

## Set 6: RSA and DSA

- [x] Challenge 41: Implement unpadded message recovery oracle
- [x] Challenge 42: Bleichenbacher's e=3 RSA Attack
- [x] Challenge 43: DSA key recovery from nonce
- [x] Challenge 44: DSA nonce recovery from repeated nonce
- [x] Challenge 45: DSA parameter tampering
- [x] Challenge 46: RSA parity oracle
- [x] Challenge 47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
- [x] Challenge 48: Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

## Set 7: Hashes

- [ ] Challenge 49: CBC-MAC Message Forgery
- [ ] Challenge 50: Hashing with CBC-MAC
- [ ] Challenge 51: Compression Ratio Side-Channel Attacks
- [ ] Challenge 52: Iterated Hash Function Multicollisions
- [ ] Challenge 53: Kelsey and Schneier's Expandable Messages
- [ ] Challenge 54: Kelsey and Kohno's Nostradamus Attack
- [ ] Challenge 55: MD4 Collisions
- [ ] Challenge 56: RC4 Single-Byte Biases

## Set 8: Abstract Algebra

- [ ] Challenge 57: Diffie-Hellman Revisited: Small Subgroup Confinement
- [ ] Challenge 58: Pollard's Method for Catching Kangaroos
- [ ] Challenge 59: Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
- [ ] Challenge 60: Single-Coordinate Ladders and Insecure Twists
- [ ] Challenge 61: Duplicate-Signature Key Selection in ECDSA (and RSA)
- [ ] Challenge 62: Key-Recovery Attacks on ECDSA with Biased Nonces
- [ ] Challenge 63: Key-Recovery Attacks on GCM with Repeated Nonces
- [ ] Challenge 64: Key-Recovery Attacks on GCM with a Truncated MAC
