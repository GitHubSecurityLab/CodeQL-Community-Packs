use rand::{rngs::OsRng, RngCore};
use ring::aead::{UnboundKey, AES_256_GCM};

pub fn test_os_rng_logged_key() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key); // $ Source[rust/cleartext-logging-key-material]
    println!("key: {}", hex::encode(key)); // $ Alert[rust/cleartext-logging-key-material]
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_thread_rng_logged_key() {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key); // $ Source[rust/cleartext-logging-key-material]
    println!("key: {}", hex::encode(key)); // $ Alert[rust/cleartext-logging-key-material]
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_os_rng_request_id() {
    let mut request_id = [0u8; 32];
    OsRng.fill_bytes(&mut request_id);
    println!("request id: {}", hex::encode(request_id));
}

pub fn test_thread_rng_key_not_logged() {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    println!("key length: {}", key.len());
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_os_rng_try_logged_key() {
    let mut key = [0u8; 32];
    OsRng.try_fill_bytes(&mut key).unwrap(); // $ Source[rust/cleartext-logging-key-material]
    println!("key: {}", hex::encode(key)); // $ Alert[rust/cleartext-logging-key-material]
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_thread_rng_try_request_id() {
    let mut request_id = [0u8; 32];
    rand::thread_rng().try_fill_bytes(&mut request_id).unwrap();
    println!("request id: {}", hex::encode(request_id));
}
