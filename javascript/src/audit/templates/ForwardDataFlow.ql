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
 import ForwardDataFlow::PathGraph
 
 module ForwardDataFlowConfig implements DataFlow::ConfigSig { 
   predicate isSource(DataFlow::Node source) {
     // Define the source to run the forward dataflow from. Eg:
     // source = API::moduleImport(_).getMember("method").getReturn().asSource()
     none()
   }

   predicate isSink(DataFlow::Node sink) { any() }
 }

 module ForwardDataFlow = TaintTracking::Global<ForwardDataFlowConfig>;
 
 from ForwardDataFlow::PathNode source, ForwardDataFlow::PathNode sink
 where ForwardDataFlow::flowPath(source, sink)
 select sink.getNode(), source, sink, "This node receives taint from $@.", source.getNode(),
   "this source"
 