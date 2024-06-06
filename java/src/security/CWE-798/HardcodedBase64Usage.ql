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
// Internal
import ghsl.Encoding
import ghsl.Hardcoded

module HardcodedPasswordBase64 implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Hardcoded }

  predicate isSink(DataFlow::Node sink) { sink instanceof Base64::Decoding }
}

module HardcodedPasswordBase64Flow = TaintTracking::Global<HardcodedPasswordBase64>;

import HardcodedPasswordBase64Flow::PathGraph

from HardcodedPasswordBase64Flow::PathNode source, HardcodedPasswordBase64Flow::PathNode sink
where HardcodedPasswordBase64Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Sensitive data is being logged $@.", source.getNode(),
  "user-provided value"
