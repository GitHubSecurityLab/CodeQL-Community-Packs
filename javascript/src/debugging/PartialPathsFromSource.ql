/**
 * @name Partial Path Query from Source
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id js/debugging/partial-path-from-source
 * @tags debugging
 */

import javascript
import ghsl
import DataFlow

// Partial Graph
module PartialFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof AllSources
  }

  predicate isSink(DataFlow::Node sink) { none() }
}

int explorationLimit() { result = 10 }

private module PartialFlows = DataFlow::Global<PartialFlowConfig>;

private module PartialFlowsGraph = PartialFlows::FlowExplorationFwd<explorationLimit/0>;

private import PartialFlowsGraph::PartialPathGraph

from PartialFlowsGraph::PartialPathNode source, PartialFlowsGraph::PartialPathNode sink
where
  /// Filter by location
  // filterByLocation(source.getNode(), "main.js", _) and
  PartialFlowsGraph::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
