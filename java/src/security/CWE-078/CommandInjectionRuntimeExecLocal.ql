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

import DataFlow::PathGraph
import ghsl.CommandInjectionRuntimeExec

class LocalSource extends Source {
  LocalSource() { this instanceof LocalUserInput }
}

from
  DataFlow::PathNode source, DataFlow::PathNode sink, ExecTaintConfiguration2 conf,
  MethodAccess call, DataFlow::Node sourceCmd, DataFlow::Node sinkCmd,
  ExecTaintConfiguration confCmd
where
  call.getMethod() instanceof RuntimeExecMethod and
  // this is a command-accepting call to exec, e.g. rt.exec(new String[]{"/bin/sh", ...})
  (
    confCmd.hasFlow(sourceCmd, sinkCmd) and
    sinkCmd.asExpr() = call.getArgument(0)
  ) and
  // it is tainted by untrusted user input
  (
    conf.hasFlow(source.getNode(), sink.getNode()) and
    sink.getNode().asExpr() = call.getArgument(0)
  )
select sink, source, sink,
  "Call to dangerous java.lang.Runtime.exec() with command '$@' with arg from untrusted input '$@'",
  sourceCmd, sourceCmd.toString(), source.getNode(), source.toString()
