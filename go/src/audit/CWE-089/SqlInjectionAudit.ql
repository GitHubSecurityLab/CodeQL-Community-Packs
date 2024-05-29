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
import semmle.go.security.SqlInjectionCustomizations
import DataFlow::PathGraph
import ghsl.Utils

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DynamicStrings }

  predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    NoSql::isAdditionalMongoTaintStep(pred, succ)
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

/** Tracks taint flow for reasoning about SQL-injection vulnerabilities. */
module Flow = TaintTracking::Global<Config>;

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on a $@.", source.getNode(),
  "user-provided value"
