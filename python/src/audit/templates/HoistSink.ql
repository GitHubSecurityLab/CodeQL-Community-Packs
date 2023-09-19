/**
 * @name Sink Hoisting to method parameter
 * @description Hoist a sink using partial dataflow
 * @kind table
 * @id githubsecuritylab/sink-hoister
 * @tags template
 */

import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import PartialFlow::PartialPathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { none() }

  predicate isSink(DataFlow::Node sink) {
    // Define the sink to be hoisted here. Eg:
    // exists(DataFlow::CallCfgNode call |
    //   call = API::moduleImport("sample").getMember("sink").getACall() and
    //   sink = call.getArg(0)
    // )
    none()
  }
}

private module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

int explorationLimit() { result = 10 }

private module PartialFlow = MyFlow::FlowExploration<explorationLimit/0>;

from PartialFlow::PartialPathNode n, int dist
where
  PartialFlow::partialFlowRev(n, _, dist) and
  n.getNode() instanceof DataFlow::ParameterNode
select dist, n
