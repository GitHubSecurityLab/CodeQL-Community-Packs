use ring::aead::{UnboundKey, AES_256_GCM};

fn fill_from(source: &[u8], out: &mut [u8]) {
    out.copy_from_slice(source);
}

// A zero buffer that a call fills through a mutable reference is not a hard-coded key.
pub fn test_buffer_filled_through_a_mutable_reference(seed: &[u8]) {
    let mut key = [0u8; 32];
    fill_from(seed, &mut key);
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

// A zero buffer that is assembled with slice copies is not a hard-coded key.
pub fn test_buffer_filled_by_slice_copies(first: &[u8], second: &[u8]) {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(first);
    key[16..].copy_from_slice(second);
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

// A zero buffer that nothing fills is still a hard-coded key.
pub fn test_buffer_never_filled() {
    let key = [0u8; 32];
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}

// A constant buffer that is only read, also through a mutable reference of another buffer, is still
// a hard-coded key.
pub fn test_other_buffer_filled() {
    let key = [7u8; 32];
    let mut other = [0u8; 32];
    fill_from(&[1u8; 32], &mut other);
    let _ = UnboundKey::new(&AES_256_GCM, &key);
}
