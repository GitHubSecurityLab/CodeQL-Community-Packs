/**
 * Provides a taint tracking configuration to find use of broken or weak
 * cryptographic hashing algorithms on sensitive data.
 */

import csharp
import semmle.code.csharp.security.SensitiveActions
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.dataflow.TaintTracking

/**
 * A taint tracking configuration from sensitive expressions to broken or weak
 * hashing sinks.
 */
module WeakHashingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node.asExpr() instanceof SensitiveExpr }

  predicate isSink(DataFlow::Node node) { node instanceof WeakSensitiveDataHashingSink }

  predicate isBarrierIn(DataFlow::Node node) {
    // make sources barriers so that we only report the closest instance
    isSource(node)
  }

  predicate isBarrierOut(DataFlow::Node node) {
    // make sinks barriers so that we only report the closest instance
    isSink(node)
  }
}

module WeakHashingFlow = TaintTracking::Global<WeakHashingConfig>;

// TODO: rewrite with data extensions in mind, ref the Swift implementation
class WeakSensitiveDataHashingSink extends DataFlow::Node {   
  string algorithm;

  WeakSensitiveDataHashingSink() {
    // a call to System.Security.Cryptography.MD5.ComputeHash, ComputeHashAsync, HashData or HashDataAsync
    exists(MethodCall call, string name |
      (
        call.getTarget().getName() = name
        and name in ["ComputeHash", "ComputeHashAsync", "HashData", "HashDataAsync"]
      )
      // with this as the first argument - not arg 0, since arg 0 is 'this' for methods
      and call.getArgument(0) = this.asExpr()
      and
      // the call is to a method in the System.Security.Cryptography.MD5 class
      // or the System.Security.Cryptography.SHA1 class
      (
        call.getQualifier().getType().getName() = algorithm
        and algorithm in ["MD5","SHA1"]
      )
    )
  }

  string getAlgorithm() {
    result = algorithm
  }
}
