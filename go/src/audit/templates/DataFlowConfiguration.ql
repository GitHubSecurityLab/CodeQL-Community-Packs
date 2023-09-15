/**
 * @name DataFlow configuration
 * @description DataFlow TaintTracking configuration 
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @id seclab/dataflow-query
 * @tags audit
 */

import go
import semmle.go.dataflow.TaintTracking
import MyFlow::PathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Define your source nodes here. eg:
    // exists(DataFlow::CallNode call |
    //   call.getTarget().hasQualifiedName(_, "source") and
    //   call = source
    // )
    none()
  }

  predicate isSink(DataFlow::Node sink) {
    // Define your sink nodes here. eg:
    // exists(DataFlow::CallNode call |
    //   call.getTarget().hasQualifiedName(_, "sink") and
    //   call.getArgument(0) = sink
    //   )
    none()
  }
}

module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Sample TaintTracking query"
