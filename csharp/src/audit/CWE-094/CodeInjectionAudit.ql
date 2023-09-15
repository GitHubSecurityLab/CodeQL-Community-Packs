/**
 * @name Audit: Use of Code Injection sink
 * @description Treating externally controlled strings as code can allow an attacker to execute
 *              malicious code.
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.0
 * @precision low
 * @id cs/audit/code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-096
 *       audit
 */

import csharp
import semmle.code.csharp.security.dataflow.CodeInjectionQuery

from DataFlow::Node sink
where sink instanceof Sink
select sink, "Usage of Code Injection sink"
