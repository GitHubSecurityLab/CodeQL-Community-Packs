/**
 * @name SQL query built from user-controlled sources
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id githubsecuritylab/audit/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       heuristic
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

class DatabaseExtentions extends DataFlow::Node {
  DatabaseExtentions() {
    exists(CallNode call |
      call.getFunction().(AttrNode).getName() in ["execute", "raw"] and
      this.asCfgNode() = call.getArg(0)
    ) and
    this.getScope().inSource()
  }
}

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
class SqlInjectionHeuristic extends TaintTracking::Configuration {
  SqlInjectionHeuristic() { this = "SqlInjectionHeuristic" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlInjection::Source }

  override predicate isSink(DataFlow::Node sink) { sink instanceof DatabaseExtentions }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

from SqlInjectionHeuristic config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
