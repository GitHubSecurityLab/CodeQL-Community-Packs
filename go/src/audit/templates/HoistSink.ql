/**
 * @name Sink Hoisting to method parameter
 * @description Hoist a sink using partial dataflow
 * @kind table
 * @id githubsecuritylab/sink-hoister
 * @tags template
 */

import go
import semmle.go.dataflow.TaintTracking
import PartialFlow::PartialPathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { none() }

  predicate isSink(DataFlow::Node sink) {
    // Define the sink to be hoisted here. eg:
    // exists(DataFlow::CallNode call |
    //   call.getTarget().hasQualifiedName(_, "sink") and
    //   call.getArgument(0) = sink
    //   )
    none()
  }
}

private module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Make<..>

int explorationLimit() { result = 10 }

private module PartialFlow = MyFlow::FlowExplorationRev<explorationLimit/0>;

from PartialFlow::PartialPathNode n, int dist
where
  PartialFlow::partialFlow(n, _, dist) and
  n.getNode() instanceof DataFlow::ParameterNode
select dist, n
