/**
 * @name Partial Path Query from Source
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id py/debugging/partial-path-from-source
 * @tags debugging
 */

import go
import ghsl
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking

// Partial Graph
module PartialFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof AllSources
  }

  predicate isSink(DataFlow::Node sink) { none() }
}

int explorationLimit() { result = 10 }

module PartialFlows = DataFlow::Global<PartialFlowConfig>;

module PartialFlowsGraph = PartialFlows::FlowExplorationFwd<explorationLimit/0>;

import PartialFlowsGraph::PartialPathGraph

from PartialFlowsGraph::PartialPathNode source, PartialFlowsGraph::PartialPathNode sink
where
  /// Filter by location
  //   filterByLocation(source.getNode(), "main.go", _)
  PartialFlowsGraph::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
