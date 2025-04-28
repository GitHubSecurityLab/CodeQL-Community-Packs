/**
 * @name Backwards Dataflow
 * @description Backwards Dataflow (Note: backwards (partial) dataflow works differently in CodeQL for JavaScript, e.g. no PartialPathGraph is available.)
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @id githubsecuritylab/backwards-dataflow
 * @tags template
 */

 import javascript
 import BackwardDataFlow::PathGraph
 
 module BackwardDataFlowConfig implements DataFlow::ConfigSig { 
  predicate isSource(DataFlow::Node source) { any() }
 
  predicate isSink(DataFlow::Node sink) {
     // Define the sink to run the backwards dataflow from. Eg:
     // sink = API::moduleImport("module").getMember("method").getParameter(0).asSink()
     none()
   }
 }

 module BackwardDataFlow = TaintTracking::Global<BackwardDataFlowConfig>;
 
 from BackwardDataFlow::PathNode source, BackwardDataFlow::PathNode sink
 where BackwardDataFlow::flowPath(source, sink)
 select sink.getNode(), source, sink, "This node receives taint from $@.", source.getNode(),
   "this source"
 