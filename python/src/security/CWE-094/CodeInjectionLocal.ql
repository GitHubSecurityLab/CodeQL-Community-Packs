/**
 * @name Code injection
 * @description Interpreting unsanitized user input as code allows a malicious user to perform arbitrary
 *              code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10.0
 * @sub-severity critical
 * @precision low
 * @id githubsecuritylab/code-injection
 * @tags security
 *       external/owasp/owasp-a1
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-116
 *       local
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import github.LocalSources
private import semmle.python.security.dataflow.CodeInjectionCustomizations

private module CodeInjectionConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Range }

  predicate isSink(DataFlow::Node sink) { sink instanceof CodeInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CodeInjection::Sanitizer }
}

module CodeInjectionFlows = TaintTracking::Global<CodeInjectionConfiguration>;

import CodeInjectionFlows::PathGraph

from CodeInjectionFlows::PathNode source, CodeInjectionFlows::PathNode sink
where CodeInjectionFlows::flowPath(source, sink)
select sink.getNode(), source, sink, "This $@ is written to a log file.", source.getNode(),
  "potentially sensitive information"
