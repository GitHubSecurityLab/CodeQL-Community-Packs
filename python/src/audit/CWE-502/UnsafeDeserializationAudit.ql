/**
 * @name Audit: Usage of Deserializing function
 * @description Deserializing user-controlled data may allow attackers to execute arbitrary code.
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.5
 * @sub-severity low
 * @precision very-low
 * @id py/audit/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       audit
 */

import python
import semmle.python.Concepts
import semmle.python.ApiGraphs
private import semmle.python.security.dataflow.UnsafeDeserializationCustomizations

from DataFlow::Node sink
where sink instanceof UnsafeDeserialization::Sink and sink.getScope().inSource()
select sink, "Usage of Deserializing function"
