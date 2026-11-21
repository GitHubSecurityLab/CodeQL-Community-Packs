use ring::aead::{UnboundKey, AES_256_GCM};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

// key buffer is overwritten with random bytes before use: safe
pub fn test_ring_good() {
    let rand = SystemRandom::new();
    // initialized with a constant, then overwritten with random bytes
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    rand.fill(&mut key_bytes).unwrap();
    let _ = UnboundKey::new(&AES_256_GCM, &key_bytes);
}

pub fn test_ring_bad() {
    let key_bytes = [7u8; 32]; // $ Alert[rust/hardcoded-cryptographic-key]
    let _ = UnboundKey::new(&AES_256_GCM, &key_bytes); // $ Sink
}

pub fn test_ring_hmac_bad(msg: &[u8]) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"shared authentication key"); // $ Alert[rust/hardcoded-cryptographic-key]
    hmac::sign(&key, msg)
}

pub fn test_ring_hmac_good(key_value: &[u8], msg: &[u8]) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_value);
    hmac::sign(&key, msg)
}
