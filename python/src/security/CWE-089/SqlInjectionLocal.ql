/**
 * @name SQL query built from user-controlled sources
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10.0
 * @sub-severity critical
 * @precision low
 * @id githubsecuritylab/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/owasp-a1
 *       local
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.BarrierGuards
import DataFlow::PathGraph
import github.LocalSources
private import semmle.python.security.dataflow.SqlInjectionCustomizations

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
class SQLInjectionConfiguration extends TaintTracking::Configuration {
  SQLInjectionConfiguration() { this = "LocalSQLInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Range }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

from SQLInjectionConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
