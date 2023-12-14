/**
 * @name Sink Hoisting to method parameter
 * @description Hoist a sink using partial dataflow
 * @kind table
 * @id githubsecuritylab/sink-hoister
 * @tags template
 */

import java
import semmle.code.java.dataflow.TaintTracking
import PartialFlow::PartialPathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { none() }

  predicate isSink(DataFlow::Node sink) {
    // Define the sink to be hoisted here. Eg:
    // exists(MethodAccess ma, Method m |
    //   ma.getMethod() = m and
    //   m.getName() = "sink" and
    //   ma.getArgument(0) = sink.asExpr()
    //)
    none()
  }
}

private module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

int explorationLimit() { result = 10 }

private module PartialFlow = MyFlow::FlowExplorationRev<explorationLimit/0>;

from PartialFlow::PartialPathNode n, int dist
where
  PartialFlow::partialFlow(n, _, dist) and
  n.getNode() instanceof DataFlow::ExplicitParameterNode
select dist, n
