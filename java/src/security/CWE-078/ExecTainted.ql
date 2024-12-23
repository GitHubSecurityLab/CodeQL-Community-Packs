/**
 * @name Uncontrolled command line (experimental sinks)
 * @description Using externally controlled strings in a command line is vulnerable to malicious
 *              changes in the strings (includes experimental sinks).
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id githubsecuritylab/java/command-line-injection-experimental
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.security.CommandLineQuery
import InputToArgumentToExecFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow

// This is a clone of query `java/command-line-injection` that also includes experimental sinks.
from
  InputToArgumentToExecFlow::PathNode source, InputToArgumentToExecFlow::PathNode sink, Expr execArg
where execIsTainted(source, sink, execArg)
select execArg, source, sink, "This command line depends on a $@.", source.getNode(),
  "user-provided value"
