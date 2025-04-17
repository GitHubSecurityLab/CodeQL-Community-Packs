/**
 * @name Partial Path Query from Sink
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id go/debugging/partial-path-from-sink
 * @tags debugging
 */

import go
import ghsl
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking

// Partial Graph
module PartialFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { any() }

  predicate isSink(DataFlow::Node sink) { sink instanceof AllSinks }
}

int explorationLimit() { result = 10 }

private module PartialFlows = DataFlow::Global<PartialFlowConfig>;

private module PartialFlowsGraph = PartialFlows::FlowExplorationRev<explorationLimit/0>;

private import PartialFlowsGraph::PartialPathGraph

from PartialFlowsGraph::PartialPathNode source, PartialFlowsGraph::PartialPathNode sink
where
  /// Only show sinks from a certain file
  // findByLocation(sink.getNode(), "main.go", _) and
  /// Only show sources that match our criteria
  // checkSource(source.getNode()) and
  /// Partical Path
  PartialFlowsGraph::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"