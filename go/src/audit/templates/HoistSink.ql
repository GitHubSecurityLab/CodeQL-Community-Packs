/**
 * @name Sink Hoisting to method parameter
 * @description Hoist a sink using partial dataflow
 * @kind problem
 * @precision low
 * @problem.severity error
 * @id seclab/sink-hoister
 * @tags audit
 */

import go 
import semmle.go.dataflow.TaintTracking
import PartialFlow::PartialPathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    none()
  }

  predicate isSink(DataFlow::Node sink) {
    // Define the sink to be hoisted here. eg:
    // exists(DataFlow::CallNode call |
    //   call.getTarget().hasQualifiedName(_, "sink") and
    //   call.getArgument(0) = sink
    //   )
    none()
  }
}

private module MyFlow = TaintTracking::Make<MyConfig>; // or DataFlow::Make<..>
int explorationLimit() { result = 10 }
private module PartialFlow = MyFlow::FlowExploration<explorationLimit/0>;

from PartialFlow::PartialPathNode n, int dist
where PartialFlow::hasPartialFlowRev(n, _, dist) and
  n.getNode() instanceof DataFlow::ParameterNode 
select dist, n
