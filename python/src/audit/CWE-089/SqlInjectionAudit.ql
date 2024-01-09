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
private import semmle.python.security.dataflow.SqlInjectionCustomizations
import ghsl.Utils

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
module SqlInjectionHeuristicConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DynamicStrings }

  predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

module SqlInjectionHeuristicFlow = TaintTracking::Global<SqlInjectionHeuristicConfig>;

import SqlInjectionHeuristicFlow::PathGraph //importing the path graph from the module

from SqlInjectionHeuristicFlow::PathNode source, SqlInjectionHeuristicFlow::PathNode sink
where SqlInjectionHeuristicFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on a $@.", source.getNode(),
  "user-provided value"
