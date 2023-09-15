/**
 * @name Audit: Usage of Command Injection sink
 * @description Using externally controlled strings in a command line may allow a malicious
 *              user to change the meaning of the command.
 * @kind problem
 * @problem.severity error
 * @security-severity 2.0
 * @precision low
 * @id cs/audit/command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       audit
 */

import csharp
import semmle.code.csharp.security.dataflow.CommandInjectionQuery

from DataFlow::Node sink
where sink instanceof Sink
select sink, "Usage of Command Injection sink"
