/**
 * @name Audit - SQL Injection using format strings
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 2.5
 * @sub-severity low
 * @precision very-low
 * @id githubsecuritylab/audit/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       audit
 */

import go
import semmle.go.security.SqlInjection
import DataFlow::PathGraph
import ghsl.Utils

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
class SqlInjectionAudit extends TaintTracking::Configuration {
  SqlInjectionAudit() { this = "SqlInjectionAudit" }

  override predicate isSource(DataFlow::Node source) { source instanceof DynamicStrings }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

from SqlInjectionAudit config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
