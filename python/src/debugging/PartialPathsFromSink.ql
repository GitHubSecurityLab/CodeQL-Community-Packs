/**
 * @name Partial Path Query from Sink
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id py/debugging/partial-path-from-sink
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
  // findByLocation(sink.getNode(), "File.java", _) and
  /// Only show sources that match our criteria
  // checkSource(source.getNode()) and
  /// Partical Path
  PartialFlowsGraph::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"