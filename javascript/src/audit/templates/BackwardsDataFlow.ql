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
 import DataFlow::PathGraph
 import semmle.javascript.explore.BackwardDataFlow
 
 class BackwardDataFlowConfig extends TaintTracking::Configuration {
   BackwardDataFlowConfig() { this = "BackwardDataFlowConfig" }
 
   // `isSource` is ignored when `semmle.javascript.explore.BackwardDataFlow` is imported.
 
   override predicate isSink(DataFlow::Node sink) {
     // Define the sink to run the backwards dataflow from. Eg:
     // sink = API::moduleImport("module").getMember("method").getParameter(0).asSink()
     none()
   }
 }
 
 from BackwardDataFlowConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "This node receives taint from $@.", source.getNode(),
   "this source"
 