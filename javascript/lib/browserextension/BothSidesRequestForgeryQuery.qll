/**
 * Provides a taint-tracking configuration for reasoning about client-side
 * request forgery.
 *
 * Note, for performance reasons: only import this file if
 * the `Configuration` class is needed, otherwise
 * `RequestForgeryCustomizations` should be imported instead.
 */

 import javascript
 import semmle.javascript.security.dataflow.UrlConcatenation
 import semmle.javascript.security.dataflow.RequestForgeryCustomizations::RequestForgery
 import BrowserAPI
 
 /**
  * A taint tracking configuration for client-side request forgery.
  * Server side is disabled since this is in the browser, but the extra models can be enabled for extra coverage
  */
 class Configuration extends TaintTracking::Configuration {
   Configuration() { this = "ClientSideRequestForgery" }
 
   override predicate isSource(DataFlow::Node source) {
     exists(Source src |
       source = src and
       not src.isServerSide()
     ) or 
    source instanceof OnMessageExternal or source instanceof OnConnectExternal
   }
 
   override predicate isSink(DataFlow::Node sink) { sink instanceof Sink }
 
   override predicate isSanitizer(DataFlow::Node node) {
     super.isSanitizer(node) or
     node instanceof Sanitizer
   }
 
   override predicate isSanitizerOut(DataFlow::Node node) { sanitizingPrefixEdge(node, _) }
 
   override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
     isAdditionalRequestForgeryStep(pred, succ)
   }
  }

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