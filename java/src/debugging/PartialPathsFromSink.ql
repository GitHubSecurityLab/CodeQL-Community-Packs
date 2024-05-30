/**
 * @name Partial Path Query from Sink
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id java/debugging/partial-path-from-sink
 * @tags debugging
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
import Helper

// Partial Graph
private module RemoteFlowsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { any() }

  predicate isSink(DataFlow::Node sink) {
    // All calls for a specific class/type
    exists(MethodAccess ma | ma = findAllMethodAccessesByType("Files") |
      sink.asExpr() = ma.getAnArgument()
    )
  }
}

int explorationLimit() { result = 10 }

private module RemoteFlows = DataFlow::Global<RemoteFlowsConfig>;

private module RemoteFlowsPartial = RemoteFlows::FlowExploration<explorationLimit/0>;

private import RemoteFlowsPartial::PartialPathGraph

from RemoteFlowsPartial::PartialPathNode source, RemoteFlowsPartial::PartialPathNode sink
where
  // Only show sinks from a certain file
  // findByLocation(sink.getNode(), "SqlInjectionChallenge.java", _) and
  // Only show sources that match our criteria
  // checkSource(source.getNode()) and
  // Partical Path
  RemoteFlowsPartial::partialFlowRev(source, sink, _)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
