/**
 * @name Cleartext logging of cryptographic key material
 * @description Writing a generated cryptographic key to a log or to the console
 *              exposes it to anyone who can read the output, allowing them to
 *              decrypt or forge the data it protects.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision medium
 * @id githubsecuritylab/rust/cleartext-logging-of-key-material
 * @tags security
 *       experimental
 *       external/cwe/cwe-312
 *       external/cwe/cwe-532
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.security.CleartextLoggingExtensions
import common.CryptoKeyMaterial

/**
 * A buffer that has just been filled with random bytes.
 */
private class RandomlyFilledBuffer extends DataFlow::PostUpdateNode {
  RandomlyFilledBuffer() {
    exists(Expr buffer, Expr filled |
      randomFillCall(_, buffer) and
      (if buffer instanceof RefExpr then filled = buffer.(RefExpr).getExpr() else filled = buffer) and
      this.getPreUpdateNode().asExpr() = filled
    )
  }
}

/** Holds if `node` flows locally to a return value of `wrapper`. */
private predicate isReturnedBy(DataFlow::Node node, Callable wrapper) {
  exists(DataFlow::Node returned |
    returned.asExpr() = wrapper.getBody()
    or
    exists(ReturnExpr ret |
      ret.getEnclosingCfgScope() = wrapper and returned.asExpr() = ret.getExpr()
    )
  |
    DataFlow::localFlow(node, returned)
  )
}

/** A key returned by an API that specifically generates cryptographic keys. */
private class GeneratedCryptographicKey extends DataFlow::Node {
  GeneratedCryptographicKey() {
    this.asExpr().(Call).getStaticTarget().getCanonicalPath() =
      ["<crypto_common::KeyInit>::generate_key", "<crypto_common::KeyIvInit>::generate_key"]
  }
}

/**
 * Generated material, with returned random buffers sourced at each wrapper call
 * rather than conflating independent generated values at the fill in the helper.
 */
class GeneratedKeyMaterial extends DataFlow::Node {
  GeneratedKeyMaterial() {
    this instanceof GeneratedCryptographicKey
    or
    exists(RandomlyFilledBuffer buffer |
      this = buffer and not isReturnedBy(buffer, _)
      or
      isReturnedBy(buffer, this.asExpr().(Call).getStaticTarget()) and
      // Do not retain a shared inner-call source in unsupported nested wrappers.
      not isReturnedBy(this, _)
    )
  }
}

/**
 * A taint-tracking configuration for generated key material that flows to a
 * cryptographic key sink and to a logging sink.
 */
module CleartextLoggingOfKeyMaterialConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof GeneratedKeyMaterial }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof CleartextLogging::Sink
    or
    sink.(CryptographicKeySink).getKind() = ["key", "password"]
  }

  predicate isBarrier(DataFlow::Node barrier) {
    barrier instanceof CleartextLogging::Barrier
    or
    isNonRevealingProperty(barrier.asExpr())
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // flow from `a` to `&a`
    node2.asExpr().(RefExpr).getExpr() = node1.asExpr()
    or
    keyMaterialConversionStep(node1, node2)
    or
    keyMaterialEncodingStep(node1, node2)
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    // flow out from tuple content at logging sinks
    node instanceof CleartextLogging::Sink and
    c.getAReadContent() instanceof DataFlow::TuplePositionContent
  }
}

module CleartextLoggingOfKeyMaterialFlow =
  TaintTracking::Global<CleartextLoggingOfKeyMaterialConfig>;

import CleartextLoggingOfKeyMaterialFlow::PathGraph

from
  CleartextLoggingOfKeyMaterialFlow::PathNode source,
  CleartextLoggingOfKeyMaterialFlow::PathNode sink
where
  CleartextLoggingOfKeyMaterialFlow::flowPath(source, sink) and
  sink.getNode() instanceof CleartextLogging::Sink and
  (
    // Key-generation APIs already establish that the value is a key.
    source.getNode() instanceof GeneratedCryptographicKey
    or
    // Generic random buffers, including wrapper results, still require key use.
    exists(CryptographicKeySink keySink | keySink.getKind() = ["key", "password"] |
      CleartextLoggingOfKeyMaterialFlow::flow(source.getNode(), keySink)
    )
  )
select sink.getNode(), source, sink, "This operation writes $@ to a log.", source,
  "generated cryptographic key material"
