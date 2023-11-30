/**
 * @name Sink Hoisting to method parameter
 * @description Hoist a sink using partial dataflow
 * @kind table
 * @id githubsecuritylab/sink-hoister
 * @tags template
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import PartialFlow::PartialPathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { none() }

  predicate isSink(DataFlow::Node sink) {
    // Define the sink to be hoisted here. Eg:
    // exists(Call c |
    //   c.getTarget().hasName("sink") and
    //   sink.asExpr() = c.getArgument(0)
    // )
    none()
  }
}

private module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

int explorationLimit() { result = 10 }

private module PartialFlow = MyFlow::FlowExplorationRev<explorationLimit/0>;

from PartialFlow::PartialPathNode n, int dist
where
  PartialFlow::partialFlow(n, _, dist) and
  exists(Parameter p | n.getNode().asParameter() = p)
select dist, n
