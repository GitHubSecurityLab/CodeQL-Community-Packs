/**
 * @name Extension API Object Injection
 * @description Injecting attacker controlled object into Chrome APIs may result in dangerous side effects.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id js/browserapi-injection-object
 * @tags security
 */

 import javascript
 import ConfigFlow::PathGraph
 import browserextension.BrowserInjectionObjectCustomizations::BrowserInjection
 import DataFlow
 private import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom as XssThroughDom
 
 
 class ObjectState extends string {
   ObjectState() { this = "Object" }
 }
 
   /**
    * Gets either a standard flow label or the partial-taint label.
    */
   string anyLabel() { result = ["data", "taint"] }
 
 
   module Config implements DataFlow::StateConfigSig {
     class FlowState extends string {
       FlowState() { this = anyLabel() or this instanceof ObjectState }
     }

     predicate isSource(DataFlow::Node source, FlowState state) {
        source instanceof Source and // optional: or source instanceof XssThroughDom::Source
        (
          state = anyLabel()
          or
          state instanceof ObjectState
        )
     }
   
     predicate isSink(DataFlow::Node sink, FlowState state) {
       sink instanceof Sink and state instanceof ObjectState
     }
 
     predicate isAdditionalFlowStep(
       DataFlow::Node src, FlowState inState, DataFlow::Node trg, FlowState outState
     ) {
       // writing a tainted value to an object property makes the object tainted with ObjectLabel
       exists(DataFlow::PropWrite write |
         write.getRhs() = src and
         inState = anyLabel() and
         trg.(DataFlow::SourceNode).flowsTo(write.getBase()) and
         outState instanceof ObjectState
       )
     }
    }
   
   module ConfigFlow = TaintTracking::GlobalWithState<Config>;
 
   from ConfigFlow::PathNode source, ConfigFlow::PathNode sink
   where ConfigFlow::flowPath(source, sink)
   select sink.getNode(), source, sink, sink.getNode() + " depends on a $@.",
     source.getNode(), "user-provided value"
 
 