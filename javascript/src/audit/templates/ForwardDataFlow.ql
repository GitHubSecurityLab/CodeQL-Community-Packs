/**
 * @name Forward Dataflow
 * @description Forward Dataflow (Note: forward (partial) dataflow works differently in CodeQL for JavaScript, e.g. no PartialPathGraph is available.)
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @id githubsecuritylab/forward-dataflow
 * @tags template
 */

 import javascript
 import DataFlow::PathGraph
 import semmle.javascript.explore.ForwardDataFlow
 
 class ForwardDataFlowConfig extends TaintTracking::Configuration {
   ForwardDataFlowConfig() { this = "ForwardDataFlowConfig" }
 
   override predicate isSource(DataFlow::Node source) {
     // Define the source to run the forward dataflow from. Eg:
     // source = API::moduleImport(_).getMember("method").getReturn().asSource()
     none()
   }
 
   // `isSink` is ignored when `semmle.javascript.explore.ForwardDataFlow` is imported.
 }
 
 from ForwardDataFlowConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "This node receives taint from $@.", source.getNode(),
   "this source"
 