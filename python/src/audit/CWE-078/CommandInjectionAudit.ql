/**
 * @name Audit: Usage of Command Injection sink
 * @description Using externally controlled strings in a command line may allow a malicious
 *              user to change the meaning of the command.
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.5
 * @sub-severity low
 * @precision very-low
 * @id githubsecuritylab/audit/command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       audit
 */

import python
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.security.dataflow.CommandInjectionCustomizations

from DataFlow::Node sink
where sink instanceof CommandInjection::Sink
select sink, "Usage of command line"
