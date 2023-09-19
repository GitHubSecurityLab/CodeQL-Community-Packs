/**
 * @name SQL query built from user-controlled sources
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

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs
import DataFlow::PathGraph
private import semmle.python.security.dataflow.SqlInjectionCustomizations
//
import github.Utils

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
class SqlInjectionHeuristic extends TaintTracking::Configuration {
  SqlInjectionHeuristic() { this = "SqlInjectionHeuristic" }

  override predicate isSource(DataFlow::Node source) { source instanceof DynamicStrings }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

from SqlInjectionHeuristic config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
