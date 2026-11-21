use ring::aead::{UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

fn make_key() -> UnboundKey {
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    SystemRandom::new().fill(&mut key_bytes).unwrap();
    println!("generated a {}-byte key", key_bytes.len()); // GOOD: only the key length is written
    UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()
}
