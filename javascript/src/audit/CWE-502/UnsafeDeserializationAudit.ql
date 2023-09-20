/**
 * @name Audit: Usage of Unsafe Deserialize sink
 * @description A Unsafe Deserialization sink is being used in your application, this can lead to remote code execution if user controled input comes into the sink
 * @kind problem
 * @problem.severity error
 * @security-severity 3.0
 * @id githubsecuritylab/audit/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-503
 *       audit
 */

import javascript
private import semmle.javascript.security.dataflow.UnsafeDeserializationCustomizations

from DataFlow::Node sink
where sink instanceof UnsafeDeserialization::Sink
select sink, "Unsafe Deserialization sink"
