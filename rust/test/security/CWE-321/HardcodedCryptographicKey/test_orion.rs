use orion::{aead, auth, pwhash};

pub fn test_orion_aead_bad() {
    let key_bytes = [3; 32]; // $ Alert[rust/hardcoded-cryptographic-key]
    let key = match aead::SecretKey::from_slice(&key_bytes) { // $ Sink
        Ok(key) => key,
        Err(_) => return,
    };
    let _ = aead::seal(&key, b"Some secret information");
}

pub fn test_orion_auth_bad() {
    let key = auth::SecretKey::from_slice(b"Hardcoded insecure secret!!!!!!!").unwrap(); // $ Alert[rust/hardcoded-cryptographic-key]
    let msg = "Some message.".as_bytes();
    let _ = auth::authenticate(&key, msg);
}

// randomly generated key: safe
pub fn test_orion_auth_good() {
    let key = auth::SecretKey::default();
    let msg = "Some message.".as_bytes();
    let _ = auth::authenticate(&key, msg);
}

pub fn test_orion_pwhash_bad() {
    let password = pwhash::Password::from_slice(b"hunter2").unwrap(); // $ Alert[rust/hardcoded-cryptographic-key]
    let _ = pwhash::hash_password(&password, 3, 1 << 16);
}
