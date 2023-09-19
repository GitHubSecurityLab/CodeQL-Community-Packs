/**
 * @name DataFlow configuration
 * @description DataFlow TaintTracking configuration
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @id githubsecuritylab/dataflow-query
 * @tags template
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import MyFlow::PathGraph

private module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Define your source nodes here. Eg:
    // exists(DataFlow::CallCfgNode call |
    //   call = API::moduleImport("sample").getMember("source").getACall() and
    //   source = call
    // )
    none()
  }

  predicate isSink(DataFlow::Node sink) {
    // Define your sink nodes here. Eg:
    // exists(DataFlow::CallCfgNode call |
    //   call = API::moduleImport("sample").getMember("sink").getACall() and
    //   sink = call.getArg(0)
    // )
    none()
  }
}

module MyFlow = TaintTracking::Global<MyConfig>; // or DataFlow::Global<..>

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Sample TaintTracking query"
