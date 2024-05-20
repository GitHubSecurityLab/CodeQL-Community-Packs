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
 import DataFlow::PathGraph
 import BrowserInjectionObjectCustomizations::BrowserInjection
 import DataFlow
 private import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom as XssThroughDom
 
 
 class ObjectLabel extends DataFlow::FlowLabel {
   ObjectLabel() {
     this = "Object"
   }
 }
 
   /**
    * Gets either a standard flow label or the partial-taint label.
    */
   DataFlow::FlowLabel anyLabel() {
     result.isDataOrTaint()
   }
 
 
   class Configuration extends TaintTracking::Configuration {
     Configuration() { this = "BrowserInjection" }
   
     override predicate isSource(DataFlow::Node source) { 
        source instanceof Source // optional: or source instanceof XssThroughDom::Source
     }
   
     override predicate isSink(DataFlow::Node sink, DataFlow::FlowLabel lbl) { 
       sink instanceof Sink and lbl instanceof ObjectLabel
     }
 
     override predicate isAdditionalFlowStep(
       DataFlow::Node src, DataFlow::Node trg, DataFlow::FlowLabel inlbl, DataFlow::FlowLabel outlbl
     ) {
       // writing a tainted value to an object property makes the object tainted with ObjectLabel
       exists(DataFlow::PropWrite write |
         write.getRhs() = src and
         inlbl = anyLabel() and
         trg.(DataFlow::SourceNode).flowsTo(write.getBase()) and
         outlbl instanceof ObjectLabel
       )
     }
    }
   
 
   from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
   where cfg.hasFlowPath(source, sink)
   select sink.getNode(), source, sink, sink.getNode() + " depends on a $@.",
     source.getNode(), "user-provided value"
 
 