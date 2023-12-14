/**
 * @name Base64 Hardcoded Password
 * @description Static hardcoded base64 password / key
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision low
 * @sub-severity high
 * @id githubsecuritylab/hardcoded-password
 * @tags security
 *       external/cwe/cwe-798
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
import DataFlow::PathGraph
// Internal
import ghsl.Encoding
import ghsl.Hardcoded

class HardcodedPasswordBase64 extends TaintTracking::Configuration {
  HardcodedPasswordBase64() { this = "HardcodedPasswordBase64" }

  override predicate isSource(DataFlow::Node source) { source instanceof Hardcoded }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Base64::Decoding }
}

// ========== Query ==========
from DataFlow::PathNode source, DataFlow::PathNode sink, HardcodedPasswordBase64 config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Sensitive data is being logged $@.", source.getNode(),
  "user-provided value"
