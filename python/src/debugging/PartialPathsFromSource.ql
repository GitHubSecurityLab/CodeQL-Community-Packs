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

import python
import ghsl
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs

// Partial Graph
module PartialFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof AllSources and
    // Make sure the source node is in the source code
    source.getScope().inSource()
  }

  predicate isSink(DataFlow::Node sink) { none() }
}

int explorationLimit() { result = 10 }

module PartialFlows = DataFlow::Global<PartialFlowConfig>;

module PartialFlowsGraph = PartialFlows::FlowExplorationFwd<explorationLimit/0>;

import PartialFlowsGraph::PartialPathGraph

from PartialFlowsGraph::PartialPathNode source, PartialFlowsGraph::PartialPathNode sink
where
  PartialFlowsGraph::partialFlow(source, sink, _) and
  /// Filter by location
  filterByLocation(source.getNode(), "app.py", _)
/// Filter by Function Parameters
// and functionParameters(sink.getNode())
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
