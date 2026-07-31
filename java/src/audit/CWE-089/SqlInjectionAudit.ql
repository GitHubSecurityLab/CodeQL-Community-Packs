/**
 * @name SQL query built from user-controlled sources
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user. This audit query reports partial flows (any
 *              source, not just recognized remote/user input) into a known SQL injection sink,
 *              which is useful for surfacing sources that are not yet modeled.
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

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.QueryInjection

private module SqlInjectionAuditConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { any() }

  predicate isSink(DataFlow::Node sink) { sink instanceof QueryInjectionSink }
}

private module SqlInjectionAuditFlow = TaintTracking::Global<SqlInjectionAuditConfig>;

int explorationLimit() { result = 10 }

private module SqlInjectionAuditPartialFlow =
  SqlInjectionAuditFlow::FlowExplorationRev<explorationLimit/0>;

import SqlInjectionAuditPartialFlow::PartialPathGraph

from
  SqlInjectionAuditPartialFlow::PartialPathNode source,
  SqlInjectionAuditPartialFlow::PartialPathNode sink
where SqlInjectionAuditPartialFlow::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "This SQL query depends on a $@.", source.getNode(),
  "user-provided value"
