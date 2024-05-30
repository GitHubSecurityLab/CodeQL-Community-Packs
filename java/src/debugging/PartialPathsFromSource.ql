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
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2

import Helper


// Partial Graph
private module RemoteFlowsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { none() }
}

int explorationLimit() { result = 10 }

private module RemoteFlows = DataFlow::Global<RemoteFlowsConfig>;

private module RemoteFlowsPartial = RemoteFlows::FlowExploration<explorationLimit/0>;

private import RemoteFlowsPartial::PartialPathGraph

from RemoteFlowsPartial::PartialPathNode source, RemoteFlowsPartial::PartialPathNode sink
where
  findByLocation(source.getNode(), "SqlInjectionChallenge.java", _) and
  isCallable(sink.getNode()) and
  RemoteFlowsPartial::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
