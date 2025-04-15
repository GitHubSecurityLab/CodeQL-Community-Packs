/**
 * @name Partial Path Query from Source
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id java/debugging/partial-path-from-source
 * @tags debugging
 */

import java
import ghsl
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

// Partial Graph
private module RemoteFlowsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof AllSources }

  predicate isSink(DataFlow::Node sink) { none() }
}

int explorationLimit() { result = 10 }

private module RemoteFlows = DataFlow::Global<RemoteFlowsConfig>;

private module RemoteFlowsPartial = RemoteFlows::FlowExplorationFwd<explorationLimit/0>;

private import RemoteFlowsPartial::PartialPathGraph

from RemoteFlowsPartial::PartialPathNode source, RemoteFlowsPartial::PartialPathNode sink
where
  /// Filter by file (line number)
  // findByLocation(source.getNode(), "File.java", _) and
  /// Filter by if the sink is callable
  // isCallable(sink.getNode()) and
  /// Perform Partial Flow query
  RemoteFlowsPartial::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
