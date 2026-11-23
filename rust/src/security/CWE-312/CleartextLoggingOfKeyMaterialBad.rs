use ring::aead::{UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

fn make_key() -> UnboundKey {
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    SystemRandom::new().fill(&mut key_bytes).unwrap();
    println!("key_bytes = {}", hex::encode(&key_bytes)); // BAD: the key is written to stdout
    UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()
}
