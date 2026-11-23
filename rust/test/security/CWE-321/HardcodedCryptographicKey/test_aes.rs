use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192};

pub fn test_aes_bad_array_literal() {
    let key = GenericArray::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]); // $ Alert[rust/hardcoded-cryptographic-key]
    let mut block = GenericArray::from([42u8; 16]);
    let cipher = Aes128::new(&key); // $ Sink
    cipher.encrypt_block(&mut block);
}

pub fn test_aes_bad_array_repeat() {
    let key = GenericArray::from([4u8; 16]); // $ Alert[rust/hardcoded-cryptographic-key]
    let mut block = GenericArray::from([42u8; 16]);
    let cipher = Aes128::new(&key); // $ Sink
    cipher.encrypt_block(&mut block);
}

// already reported by the standard `rust/hard-coded-cryptographic-value` query, so not duplicated here
pub fn test_aes_bad_new_from_slice() {
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23];
    let mut block = GenericArray::from([42u8; 16]);
    let cipher = match Aes192::new_from_slice(&key) {
        Ok(cipher) => cipher,
        Err(_) => return,
    };
    cipher.encrypt_block(&mut block);
}

// key loaded from a random source: safe
pub fn test_aes_good() {
    let mut key_bytes = [0u8; 16];
    getrandom::getrandom(&mut key_bytes).unwrap();
    let key = GenericArray::from(key_bytes);
    let mut block = GenericArray::from([42u8; 16]);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut block);
}
