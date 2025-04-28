/**
 * Provides a taint-tracking configuration for reasoning about code
 * injection vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `CodeInjection::Configuration` is needed, otherwise
 * `CodeInjectionCustomizations` should be imported instead.
 */

 import javascript
 import semmle.javascript.security.dataflow.CodeInjectionCustomizations::CodeInjection
 private import BrowserAPI
 private import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom as XssThroughDom
 
 
 
 /**
  * A taint-tracking configuration for reasoning about code injection vulnerabilities.
  */
 module Config implements DataFlow::ConfigSig { 
  predicate isSource(DataFlow::Node source) { source instanceof XssThroughDom::Source}
 
 
 
  predicate isSink(DataFlow::Node sink) { sink instanceof Sink}
 
  predicate isBarrier(DataFlow::Node node) {
     node instanceof Sanitizer
   }
 
  predicate isAdditionalFlowStep(DataFlow::Node src, DataFlow::Node trg) {
     // HTML sanitizers are insufficient protection against code injection
     src = trg.(HtmlSanitizerCall).getInput()
   }
 
  additional predicate isAdditionalLoadStep(DataFlow::Node pred, DataFlow::Node succ, string prop) {
     exists(ExecuteScript ess | ess = pred  and ess = succ and prop = ["file", "code"])
   }
 }

 module ConfigFlow = TaintTracking::Global<Config>;

//Browser Extension Models
class ExecuteScriptSink extends Sink instanceof ExecuteScript{}
class ExternalConnect1 extends Source instanceof OnConnectExternal{}
class ExternalConnect2 extends Source instanceof OnMessageExternal{}

class BrowserStep extends DataFlow::SharedFlowStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    (exists (DataFlow::ParameterNode p |
      pred instanceof SendMessage and
      succ = p and 
         p.getParameter() instanceof AddListener
    ))
  }
}

class ReturnStep extends DataFlow::SharedFlowStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    (exists (DataFlow::ParameterNode p |
      succ instanceof SendMessageReturnValue and
      pred = p.getAnInvocation().getArgument(0) and 
         p.getParameter() instanceof AddListenerReturn
    ))
  }
}

class AwaitStep extends DataFlow::SharedFlowStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ){
    succ.asExpr() instanceof AwaitExpr and pred.asExpr() = succ.asExpr().(AwaitExpr).getOperand()
  }
}