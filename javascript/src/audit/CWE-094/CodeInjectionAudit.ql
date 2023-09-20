/**
 * @name Audit: Usage of Code Injection sink
 * @description Usage of Code Injection sink
 * @kind problem
 * @problem.severity warning
 * @security-severity 3.0
 * @id githubsecuritylab/audit/code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 *       audit
 */

import javascript
import semmle.javascript.security.dataflow.CodeInjectionCustomizations

from CodeInjection::Sink sinks
select sinks, "Code Injection sink"
