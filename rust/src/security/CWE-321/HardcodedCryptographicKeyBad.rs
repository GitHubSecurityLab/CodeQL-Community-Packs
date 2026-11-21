use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

fn encrypt(block: &mut [u8; 16]) {
    let key = GenericArray::from([0u8; 16]); // BAD: the key is hard-coded
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}
