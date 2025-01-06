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
private import semmle.python.security.dataflow.SqlInjectionCustomizations
import SqlInjectionHeuristicTaint::PathGraph

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
module SqlInjectionHeuristicTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SqlInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof DatabaseExtentions }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

module SqlInjectionHeuristicTaint = TaintTracking::Global<SqlInjectionHeuristicTaintConfig>;

from SqlInjectionHeuristicTaint::PathNode source, SqlInjectionHeuristicTaint::PathNode sink
where SqlInjectionHeuristicTaint::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
