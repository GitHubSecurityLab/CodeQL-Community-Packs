/**
 * @name Command Injection into Runtime.exec() with dangerous command
 * @description Testing query. High sensitvity and precision version of java/command-line-injection, designed to find more cases of command injection in rare cases that the default query does not find
 * @kind path-problem
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

import Flow2::PathGraph

from
  Flow::PathNode sourceExec, Flow::PathNode sinkExec, Flow2::PathNode sourceTaint,
  Flow2::PathNode sinkTaint, MethodCall call
where
  call.getMethod() instanceof RuntimeExecMethod and
  (
    // this is a command-accepting call to exec, e.g. exec("/bin/sh", ...)
    Flow::flowPath(sourceExec, sinkExec) and
    sinkExec.getNode().asExpr() = call.getArgument(0)
  ) and
  (
    // it is tainted by untrusted user input
    Flow2::flowPath(sourceTaint, sinkTaint) and
    sinkTaint.getNode().asExpr() = call.getAnArgument()
  )
select sinkTaint.getNode(), sourceTaint, sinkTaint,
  "Call to dangerous java.lang.Runtime.exec() with command '$@' with arg from untrusted input '$@'",
  sourceTaint, sourceTaint.toString(), sourceTaint, sourceTaint.toString()
