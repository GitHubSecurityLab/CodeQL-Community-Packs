/**
 * @name Audit: Usage of Command Injection sink
 * @description A Command Injection sink is being used in your application, this can lead to remote code execution if user controled input comes into the sink
 * @kind problem
 * @problem.severity error
 * @security-severity 3.0
 * @id githubsecuritylab/audit/command-injection
 * @tags security
 *       external/cwe/cwe-078
 *       audit
 */

import javascript
private import semmle.javascript.security.dataflow.CommandInjectionCustomizations

from DataFlow::Node sink
where sink instanceof CommandInjection::Sink
select sink, "Command Injection sink"
