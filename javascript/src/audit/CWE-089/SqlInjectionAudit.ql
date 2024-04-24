/**
 * @name Audit: Database query built from user-controlled sources
 * @description A SQL Injection sink is being used in your application, this can lead to remote code execution if user controled input comes into the sink
 * @kind problem
 * @problem.severity error
 * @security-severity 3.0
 * @id githubsecuritylab/audit/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-090
 *       external/cwe/cwe-943
 *       audit
 */

import javascript
import semmle.javascript.security.dataflow.SqlInjectionQuery as SqlInjection
import semmle.javascript.security.dataflow.NosqlInjectionQuery as NosqlInjection

from DataFlow::Node sink
where sink instanceof SqlInjection::Sink or sink instanceof NosqlInjection::Sink
select sink, "Possible SQL Injection sink"
