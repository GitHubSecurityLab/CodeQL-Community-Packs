/**
 * @name Backwards Partial Dataflow
 * @description Backwards Partial Dataflow
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @id githubsecuritylab/backwards-partial-dataflow
 * @tags template
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import PartialFlow::PartialPathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { none() }

  predicate isSink(DataFlow::Node sink) {
    // Define the sink to run the backwards partial dataflow from. Eg:
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

from PartialFlow::PartialPathNode source, PartialFlow::PartialPathNode sink
where PartialFlow::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "This node receives taint from $@.", source.getNode(),
  "this source"
