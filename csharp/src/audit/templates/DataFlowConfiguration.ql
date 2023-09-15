/**
 * @name DataFlow configuration
 * @description DataFlow TaintTracking configuration
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @id githubsecuritylab/dataflow-query
 * @tags template
 */

import csharp
import DataFlow
import semmle.code.csharp.dataflow.TaintTracking
import MyFlow::PathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Define your source nodes here. Eg:
    // exists(Call c |
    //   c.getTarget().hasName("source") and
    //   source.asExpr() = c
    // )
    none()
  }

  predicate isSink(DataFlow::Node sink) {
    // Define your sink nodes here. Eg:
    // exists(Call c |
    //   c.getTarget().hasName("sink") and
    //   sink.asExpr() = c.getArgument(0)
    // )
    none()
  }
}

module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Sample TaintTracking query"
