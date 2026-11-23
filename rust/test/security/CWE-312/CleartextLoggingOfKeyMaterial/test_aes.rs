use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use log::info;

pub fn test_aes_bad() {
    let mut key_bytes = [0u8; 16];
    getrandom::getrandom(&mut key_bytes).unwrap(); // $ Source[rust/cleartext-logging-key-material]
    info!("generated key: {:?}", key_bytes); // $ Alert[rust/cleartext-logging-key-material]
    eprintln!("generated key: {}", hex::encode_upper(key_bytes)); // $ Alert[rust/cleartext-logging-key-material]
    let cipher = Aes128::new_from_slice(&key_bytes).unwrap();
    let mut block = GenericArray::from([42u8; 16]);
    cipher.encrypt_block(&mut block);
}
