/**
 * @name DataFlow configuration
 * @description DataFlow TaintTracking configuration
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @id githubsecuritylab/dataflow-query
 * @tags template
 */

import java
import DataFlow
import semmle.code.java.dataflow.TaintTracking
import MyFlow::PathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Define your source nodes here. Eg:
    // exists(MethodAccess ma, Method m |
    //   ma.getMethod() = m and
    //   m.getName() = "source" and
    //   ma = source.asExpr()
    //)
    none()
  }

  predicate isSink(DataFlow::Node sink) {
    // Define your sink nodes here. Eg:
    // exists(MethodAccess ma, Method m |
    //   ma.getMethod() = m and
    //   m.getName() = "sink" and
    //   ma.getArgument(0) = sink.asExpr()
    //)
    none()
  }
}

module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Sample TaintTracking query"
