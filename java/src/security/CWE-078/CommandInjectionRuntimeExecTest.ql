/**
 * @name Command Injection into Runtime.exec() with dangerous command
 * @description Testing query. High sensitvity and precision version of java/command-line-injection, designed to find more cases of command injection in rare cases that the default query does not find
 * @kind problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id githubsecuritylab/command-line-injection-extra-test
 * @tags testing
 *       test
 *       security
 *       external/cwe/cwe-078
 */

import ghsl.CommandInjectionRuntimeExec

class DataSource extends Source {
  DataSource() { this instanceof RemoteFlowSource or this instanceof LocalUserInput }
}

module Flow = TaintTracking::Global<RuntimeExec::RuntimeExecConfiguration>;

module Flow2 = TaintTracking::Global<ExecTaint::ExecTaintConfiguration>;

module FlowGraph =
  DataFlow::MergePathGraph<Flow::PathNode, Flow2::PathNode, Flow::PathGraph, Flow2::PathGraph>;

from FlowGraph::PathNode source, FlowGraph::PathNode sink
where
  Flow::flowPath(source.asPathNode1(), sink.asPathNode1()) or
  Flow2::flowPath(source.asPathNode2(), sink.asPathNode2())
select sink,
  "Call to dangerous java.lang.Runtime.exec() with command '$@' with arg from untrusted input '$@'",
  source, source.toString(), source, source.toString()
