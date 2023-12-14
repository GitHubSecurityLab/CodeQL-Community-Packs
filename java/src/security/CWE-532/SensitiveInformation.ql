/**
 * @name Sensitive information exposure through logging
 * @description Sensitive information exposure through logging
 * @kind path-problem
 * @id githubsecuritylab/sensitive-information-logging
 * @problem.severity warning
 * @security-severity 8.0
 * @precision medium
 * @tags security
 *       gdpr
 *       external/cwe/cwe-532
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
//import DataFlow::PathGraph
// Internal
import ghsl.Logging
import ghsl.SensitiveInformation

module SensitiveInformationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SensitiveInformationSources }

  predicate isSink(DataFlow::Node sink) { sink instanceof LoggingMethodsSinks }

  predicate isBarrier(DataFlow::Node node) {
    exists(Type t | t = node.getType() | t instanceof BoxedType or t instanceof PrimitiveType)
  }
}

module SensitiveInformationFlow = TaintTracking::Global<SensitiveInformationConfig>;

import SensitiveInformationFlow::PathGraph //importing the path graph from the module

// ========== Query ==========
from SensitiveInformationFlow::PathNode source, SensitiveInformationFlow::PathNode sink
where SensitiveInformationFlow::flowPath(source, sink) //using flowPath instead of hasFlowPath
select sink.getNode(), source, sink, "Sensative data is being logged $@.", source.getNode(),
  "user-provided value"
