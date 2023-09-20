/**
 * @name DataFlow configuration
 * @description DataFlow TaintTracking configuration
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @id githubsecuritylab/dataflow-query
 * @tags template
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import MyFlow::PathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Define your source nodes here
    // exists(Call c |
    //   c.getTarget().hasName("source") and
    //   c = source.asExpr()
    // )
    none()
  }

  predicate isSink(DataFlow::Node sink) {
    // Define your sink nodes here
    // exists(Call c |
    //   c.getTarget().hasName("sink") and
    //   c.getAnArgument() = sink.asExpr()
    // )
    none()
  }
}

module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Sample TaintTracking query"
