use rand::{rngs::OsRng, RngCore};
use ring::aead::{UnboundKey, AES_256_GCM};

pub fn test_os_rng_overwrites_constant() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_thread_rng_overwrites_constant() {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_os_rng_does_not_overwrite_key() {
    let key = [7u8; 32]; // $ Alert[rust/hardcoded-cryptographic-key]
    let mut request_id = [0u8; 32];
    OsRng.fill_bytes(&mut request_id);
    let _ = UnboundKey::new(&AES_256_GCM, &key); // $ Sink
}

pub fn test_thread_rng_does_not_overwrite_key() {
    let key = [7u8; 32]; // $ Alert[rust/hardcoded-cryptographic-key]
    let mut request_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut request_id);
    let _ = UnboundKey::new(&AES_256_GCM, &key); // $ Sink
}

pub fn test_os_rng_try_overwrites_constant() {
    let mut key = [0u8; 32];
    OsRng.try_fill_bytes(&mut key).unwrap();
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_thread_rng_try_does_not_overwrite_key() {
    let key = [7u8; 32]; // $ Alert[rust/hardcoded-cryptographic-key]
    let mut request_id = [0u8; 32];
    rand::thread_rng().try_fill_bytes(&mut request_id).unwrap();
    let _ = UnboundKey::new(&AES_256_GCM, &key); // $ Sink
}
