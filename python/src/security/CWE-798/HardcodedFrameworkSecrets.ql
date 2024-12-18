/**
 * @name Hard-coded credentials
 * @description Credentials are hard coded in the source code of the application.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 5.9
 * @precision medium
 * @sub-severity medium
 * @id githubsecuritylab/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-321
 *       external/cwe/cwe-798
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs
import ghsl.HardcodedSecretSinks
import HarcodedFrameworkSecretsTaint::PathGraph

class HardcodedValue extends DataFlow::Node {
  HardcodedValue() { exists(StringLiteral literal | this = DataFlow::exprNode(literal)) }
}

module HardcodedFrameworkSecretsTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof HardcodedValue }

  predicate isSink(DataFlow::Node sink) { sink instanceof CredentialSink }
}

module HarcodedFrameworkSecretsTaint = TaintTracking::Global<HardcodedFrameworkSecretsTaintConfig>;

from HarcodedFrameworkSecretsTaint::PathNode source, HarcodedFrameworkSecretsTaint::PathNode sink
where HarcodedFrameworkSecretsTaint::flowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "hardcoded credentials"
