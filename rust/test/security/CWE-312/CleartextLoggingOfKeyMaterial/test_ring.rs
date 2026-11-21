use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];
        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);
        // nonces are not secret: safe
        println!("nonce_bytes = {}", hex::encode(&nonce_bytes));
        self.0 += 1;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

pub fn test_ring_bad() -> Result<(), Unspecified> {
    let rand = SystemRandom::new();
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    rand.fill(&mut key_bytes)?; // $ Source[rust/cleartext-logging-key-material]
    println!("key_bytes = {}", hex::encode(&key_bytes)); // $ Alert[rust/cleartext-logging-key-material]

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)?;
    let mut sealing_key = SealingKey::new(unbound_key, CounterNonceSequence(1));
    let mut in_out = b"hello world".clone();
    let _tag = sealing_key.seal_in_place_separate_tag(Aad::from(b"additional public data"), &mut in_out)?;
    // ciphertext is not key material: safe
    println!("ciphertext = {}", hex::encode(&in_out));
    Ok(())
}

pub fn test_ring_good() -> Result<(), Unspecified> {
    let rand = SystemRandom::new();
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    rand.fill(&mut key_bytes)?;
    // only the length is printed: safe
    println!("key length = {}", key_bytes.len());
    let _unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)?;
    Ok(())
}

pub fn test_random_not_key() -> Result<(), Unspecified> {
    let rand = SystemRandom::new();
    let mut request_id = [0u8; 16];
    rand.fill(&mut request_id)?;
    // random bytes that are never used as a key: safe
    println!("request id = {}", hex::encode(request_id));
    Ok(())
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).unwrap();
    bytes
}

pub fn test_independent_wrapper_results() {
    let key = random_bytes();
    let _ = UnboundKey::new(&AES_256_GCM, &key);
    let request_id = random_bytes();
    // This is a different generated value, not the key above.
    println!("request id = {}", hex::encode(request_id));
}

pub fn test_logged_wrapper_key() {
    let key = random_bytes(); // $ Source[rust/cleartext-logging-key-material]
    println!("key = {}", hex::encode(key)); // $ Alert[rust/cleartext-logging-key-material]
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_logged_wrapper_non_key() {
    let request_id = random_bytes();
    // A wrapper call is not inherently a key generation API.
    println!("request id = {}", hex::encode(request_id));
}

fn nested_random_bytes() -> [u8; 32] {
    random_bytes()
}

pub fn test_independent_nested_wrapper_results() {
    let key = nested_random_bytes();
    let _ = UnboundKey::new(&AES_256_GCM, &key);
    let request_id = nested_random_bytes();
    // Independent outer calls must not share the inner random_bytes() source.
    println!("request id = {}", hex::encode(request_id));
}

fn explicitly_returned_random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).unwrap();
    return bytes;
}

pub fn test_logged_explicit_return_wrapper_key() {
    let key = explicitly_returned_random_bytes(); // $ Source[rust/cleartext-logging-key-material]
    println!("key = {}", hex::encode(key)); // $ Alert[rust/cleartext-logging-key-material]
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

pub fn test_independent_explicit_return_wrapper_results() {
    let key = explicitly_returned_random_bytes();
    let _ = UnboundKey::new(&AES_256_GCM, &key);
    let request_id = explicitly_returned_random_bytes();
    println!("request id = {}", hex::encode(request_id));
}
