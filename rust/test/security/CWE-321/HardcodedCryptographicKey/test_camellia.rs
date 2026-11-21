use camellia::cipher::generic_array::GenericArray;
use camellia::cipher::{BlockEncrypt, KeyInit};
use camellia::Camellia128;

pub fn test_camellia_bad() {
    let key = GenericArray::from([0_u8; 16]); // $ Alert[rust/hardcoded-cryptographic-key]
    let mut block = GenericArray::from(['a' as u8; 16]);
    let cipher = Camellia128::new(&key); // $ Sink
    cipher.encrypt_block(&mut block);
}
