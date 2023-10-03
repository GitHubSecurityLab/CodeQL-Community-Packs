/**
 * @name Base64 Encoding of Sensitive Information
 * @description Base64 Encoding is not an encryption algorithum and should not be used to encryption Sensitive Information
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @sub-severity high
 * @id githubsecuritylab/weak-encryption
 * @tags security
 *       external/cwe/cwe-327
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
// import DataFlow::PathGraph
// Internal
import ghsl.SensitiveInformation

class Base64Sinks extends DataFlow::Node {
  Base64Sinks() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Base64$Encoder") and
      this.asExpr() = ma
    )
  }
}

module Base64EncryptionUsageConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SensitiveInformationSources }

  predicate isSink(DataFlow::Node sink) { sink instanceof Base64Sinks }

  predicate isBarrier(DataFlow::Node node) {
    exists(Type t | t = node.getType() | t instanceof BoxedType or t instanceof PrimitiveType)
  }
}

module Base64EncryptionFlow = TaintTracking::Global<Base64EncryptionUsageConfig>;

import Base64EncryptionFlow::PathGraph //importing the path graph from the module

from Base64EncryptionFlow::PathNode source, Base64EncryptionFlow::PathNode sink //Using PathNode from the module
where Base64EncryptionFlow::flowPath(source, sink) //using flowPath instead of hasFlowPath
select sink.getNode(), source, sink, "Sensitive data is being 'encrypted' with Base64 Encoding: $@",
  source.getNode(), "user-provided value"

