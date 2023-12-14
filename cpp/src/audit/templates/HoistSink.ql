/**
 * @name Sink Hoisting to method parameter
 * @description Hoist a sink using partial dataflow
 * @kind table
 * @id githubsecuritylab/sink-hoister
 * @tags template
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import PartialFlow::PartialPathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { none() }

  predicate isSink(DataFlow::Node sink) {
    // Define the sink to be hoisted here. eg:
    // exists(Call c |
    //   c.getTarget().hasName("sink") and
    //   c.getAnArgument() = sink.asExpr()
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
  n.getNode() instanceof DataFlow::ParameterNode
select dist, n
