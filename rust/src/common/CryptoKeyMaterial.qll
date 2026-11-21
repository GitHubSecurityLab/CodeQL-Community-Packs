/**
 * Provides classes and predicates for recognizing cryptographic key material in
 * Rust code, complementing the models in `codeql/rust-all` for crates such as
 * `age`, `orion`, `ring` and `generic-array`.
 */

import rust
private import codeql.rust.dataflow.DataFlow
private import codeql.rust.security.HardcodedCryptographicValueExtensions

/**
 * Holds if `call` targets a function whose canonical path matches `pathRegex`.
 */
bindingset[pathRegex]
private predicate callTo(Call call, string pathRegex) {
  call.getStaticTarget().getCanonicalPath().regexpMatch(pathRegex)
}

/**
 * An argument to a cryptographic API that is interpreted as secret key material
 * (a key or passphrase), and that is not already modeled by `codeql/rust-all`.
 */
class AdditionalCryptographicKeySink extends DataFlow::Node {
  CryptographicValueKind kind;

  AdditionalCryptographicKeySink() {
    exists(Call call, int i | this.asExpr() = call.getPositionalArgument(i) |
      // age: passphrase-based encryption and decryption
      callTo(call,
        [
          "<age::protocol::Encryptor>::with_user_passphrase",
          "<age::protocol::decryptor::PassphraseDecryptor>::decrypt"
        ]) and
      i = 0 and
      kind = "password"
      or
      // orion: secret keys and passwords constructed from raw bytes
      callTo(call, "<orion::[a-z_:]+::SecretKey>::from_slice") and
      i = 0 and
      kind = "key"
      or
      callTo(call, "<orion::[a-z_:]+::Password>::from_slice") and
      i = 0 and
      kind = "password"
      or
      // ring: AEAD, HMAC and HKDF keys constructed from raw bytes
      callTo(call,
        [
          "<ring::aead::unbound_key::UnboundKey>::new", "<ring::hmac::Key>::new",
          "<ring::hkdf::Prk>::new_less_safe"
        ]) and
      i = 1 and
      kind = "key"
    )
  }

  /** Gets the kind of cryptographic value this sink is interpreted as. */
  CryptographicValueKind getKind() { result = kind }
}

/**
 * A value that is used as a cryptographic key or passphrase, either by an API
 * modeled in `codeql/rust-all` or by an `AdditionalCryptographicKeySink`.
 */
class CryptographicKeySink extends DataFlow::Node {
  CryptographicValueKind kind;

  CryptographicKeySink() {
    kind = this.(AdditionalCryptographicKeySink).getKind()
    or
    kind = this.(HardcodedCryptographicValue::Sink).getKind()
  }

  /** Gets the kind of cryptographic value this sink is interpreted as. */
  CryptographicValueKind getKind() { result = kind }
}

/**
 * Holds if `call` is a call to a random number generator API that fills
 * `buffer` with random bytes.
 */
predicate randomFillCall(Call call, Expr buffer) {
  callTo(call,
    [
      "<_ as ring::rand::SecureRandom>::fill", "<[^>]+ as rand_core::RngCore>::fill_bytes",
      "<[^>]+ as rand_core::RngCore>::try_fill_bytes", "<_ as rand::rng::Rng>::fill",
      "<_ as rand::rng::Rng>::try_fill", "getrandom::fill", "getrandom::getrandom"
    ]) and
  buffer = call.getPositionalArgument(0)
}

/**
 * Holds if `e` is the buffer argument of a call that fills it with random
 * bytes, or is nested inside such an argument (for example `key` in
 * `&mut key`).
 */
predicate isRandomlyFilledBuffer(Expr e) {
  exists(Expr buffer | randomFillCall(_, buffer) | e.getParentNode*() = buffer)
}

/**
 * Holds if there is a conversion from `node1` to `node2` that preserves key
 * material and that is not otherwise modeled, such as
 * `GenericArray::from([0u8; 16])` (whose `From` implementation is often not
 * resolved) or `secrecy::Secret::new(s)`.
 */
predicate keyMaterialConversionStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(Call call |
    node1.asExpr() = call.getPositionalArgument(0) and
    node2.asExpr() = call
  |
    // `T::from(x)` where the `From` implementation is not resolved
    exists(Path path | path = call.(CallExpr).getFunction().(PathExpr).getPath() |
      path.getSegment().getIdentifier().getText() = "from" and
      exists(path.getQualifier()) and
      not exists(call.getStaticTarget())
    )
    or
    // secret wrappers from the `secrecy` crate
    callTo(call,
      [
        "<secrecy::Secret>::new", "<secrecy::SecretBox>::new",
        "<secrecy::SecretString as core::convert::From>::from"
      ])
  )
}

/**
 * Holds if `node2` is an encoding (such as a hex string) of the key material
 * in `node1`.
 */
predicate keyMaterialEncodingStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(Call call |
    callTo(call, ["hex::encode", "hex::encode_upper"]) and
    node1.asExpr() = call.getPositionalArgument(0) and
    node2.asExpr() = call
  )
}

/**
 * Holds if `e` computes a property of a value, such as its length, that does
 * not reveal the value itself.
 */
predicate isNonRevealingProperty(Expr e) {
  e.(MethodCallExpr).getIdentifier().getText() = ["len", "is_empty", "capacity"]
}
