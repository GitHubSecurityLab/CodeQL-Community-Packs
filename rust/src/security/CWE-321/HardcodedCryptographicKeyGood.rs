use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

fn encrypt(block: &mut [u8; 16], key_bytes: [u8; 16]) {
    // GOOD: the key is loaded at runtime from a protected secret store
    let key = GenericArray::from(key_bytes);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}
