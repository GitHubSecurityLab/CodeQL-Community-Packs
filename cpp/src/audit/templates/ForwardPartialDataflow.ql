/**
 * @name Forward Partial Dataflow
 * @description Forward Partial Dataflow
 * @kind table
 * @id githubsecuritylab/forward-partial-dataflow
 * @tags template
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import PartialFlow::PartialPathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Define the source to run the forward partial dataflow from. Eg:
    // exists(Call c |
    //   c.getTarget().hasName("source") and
    //   c = source.asExpr()
    // )
    none()
  }

  predicate isSink(DataFlow::Node sink) { none() }
}

private module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

int explorationLimit() { result = 10 }

private module PartialFlow = MyFlow::FlowExploration<explorationLimit/0>;

from PartialFlow::PartialPathNode n, int dist
where PartialFlow::partialFlow(_, n, dist)
select dist, n
