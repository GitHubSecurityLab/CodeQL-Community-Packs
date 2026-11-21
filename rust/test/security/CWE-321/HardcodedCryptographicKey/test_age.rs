use age::secrecy::Secret;
use std::io::{Read, Write};

// Passphrase passed in from a hard-coded literal in the caller.
fn encrypt(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
    let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned())); // $ Sink
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    encrypted
}

fn decrypt(ciphertext: Vec<u8>, passphrase: &str) -> Vec<u8> {
    let decryptor = match age::Decryptor::new(&ciphertext[..]).unwrap() {
        age::Decryptor::Passphrase(d) => d,
        _ => unreachable!(),
    };
    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(&Secret::new(passphrase.to_owned()), None).unwrap(); // $ Sink
    reader.read_to_end(&mut decrypted).unwrap();
    decrypted
}

pub fn test_age_bad_indirect() {
    let passphrase = "this is not a good passphrase"; // $ Alert[rust/hardcoded-cryptographic-key]
    let ciphertext = encrypt(b"Hello world!", passphrase);
    let _ = decrypt(ciphertext, passphrase);
}

// Passphrase in-lined at the call site.
pub fn test_age_bad_inline(plaintext: &[u8]) -> Vec<u8> {
    let encryptor = age::Encryptor::with_user_passphrase(Secret::new("this is not a good passphrase".to_owned())); // $ Alert[rust/hardcoded-cryptographic-key]
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    let decryptor = match age::Decryptor::new(&encrypted[..]).unwrap() {
        age::Decryptor::Passphrase(d) => d,
        _ => unreachable!(),
    };
    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(&Secret::new("this is not a good passphrase".to_string()), None).unwrap(); // $ Alert[rust/hardcoded-cryptographic-key]
    reader.read_to_end(&mut decrypted).unwrap();
    decrypted
}

// Passphrase loaded at runtime: safe.
pub fn test_age_good() {
    let passphrase = std::env::var("AGE_PASSPHRASE").unwrap();
    let ciphertext = encrypt(b"Hello world!", &passphrase);
    let _ = decrypt(ciphertext, &passphrase);
}
