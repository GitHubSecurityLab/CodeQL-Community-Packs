/**
 * @name Command Injection into Runtime.exec() with dangerous command
 * @description High sensitvity and precision version of java/command-line-injection, designed to find more cases of command injection in rare cases that the default query does not find
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id githubsecuritylab/command-line-injection-extra
 * @tags security
 *       external/cwe/cwe-078
 */

import ghsl.CommandInjectionRuntimeExec

class RemoteSource extends Source {
  RemoteSource() { this instanceof RemoteFlowSource }
}

module Flow = TaintTracking::Global<RuntimeExec::RuntimeExecConfiguration>;

module Flow2 = TaintTracking::Global<ExecTaint::ExecTaintConfiguration>;

module FlowGraph =
  DataFlow::MergePathGraph<Flow::PathNode, Flow2::PathNode, Flow::PathGraph, Flow2::PathGraph>;

import FlowGraph::PathGraph

from FlowGraph::PathNode source, FlowGraph::PathNode sink
where
  Flow::flowPath(source.asPathNode1(), sink.asPathNode1()) or
  Flow2::flowPath(source.asPathNode2(), sink.asPathNode2())
select sink.getNode(), source, sink,
  "Call to dangerous java.lang.Runtime.exec() with command '$@' with arg from untrusted input '$@'",
  source, source.toString(), source.getNode(), source.toString()
