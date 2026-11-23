use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;

pub fn test_aes_gcm_bad(plaintext: &[u8]) -> Vec<u8> {
    let key = Aes256Gcm::generate_key(OsRng); // $ Source[rust/cleartext-logging-key-material]
    println!("AES-256-GCM key: {}", hex::encode(key)); // $ Alert[rust/cleartext-logging-key-material]
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    // nonces are not secret: safe
    println!("nonce: {}", hex::encode(nonce));
    cipher.encrypt(&nonce, plaintext).unwrap()
}

pub fn test_aes_gcm_good(plaintext: &[u8]) -> Vec<u8> {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
    // ciphertext is not key material: safe
    println!("ciphertext: {}", hex::encode(&ciphertext));
    ciphertext
}

pub fn test_generate_key_logged_and_returned() -> aes_gcm::Key<Aes256Gcm> {
    let key = Aes256Gcm::generate_key(OsRng); // $ Source[rust/cleartext-logging-key-material]
    println!("generated key: {}", hex::encode(key)); // $ Alert[rust/cleartext-logging-key-material]
    key
}

pub fn test_generate_key_returned_without_logging() -> aes_gcm::Key<Aes256Gcm> {
    Aes256Gcm::generate_key(OsRng)
}

pub fn test_generate_key_length_logged() -> aes_gcm::Key<Aes256Gcm> {
    let key = Aes256Gcm::generate_key(OsRng);
    println!("key length: {}", key.len());
    key
}
