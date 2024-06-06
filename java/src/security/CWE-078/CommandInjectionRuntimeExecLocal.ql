/**
 * @name Command Injection into Runtime.exec() with dangerous command
 * @description High sensitvity and precision version of java/command-line-injection, designed to find more cases of command injection in rare cases that the default query does not find
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id githubsecuritylab/command-line-injection-extra-local
 * @tags security
 *       local
 *       external/cwe/cwe-078
 */

import ghsl.CommandInjectionRuntimeExec

class LocalSource extends Source {
  LocalSource() { this instanceof LocalUserInput }
}

module Flow = TaintTracking::Global<RuntimeExec::RuntimeExecConfiguration>;

module Flow2 = TaintTracking::Global<ExecTaint::ExecTaintConfiguration>;

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
select sinkExec, sourceExec, sinkExec,
  "Call to dangerous java.lang.Runtime.exec() with command '$@' with arg from untrusted input '$@'",
  sourceTaint, sourceTaint.toString(), sourceExec.getNode(), sourceExec.toString()
