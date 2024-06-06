/**
 * @name Cross-Site Scripting (XSS) in JSP
 * @description Cross-Site Scripting (XSS) in JSP
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id githubsecuritylab/xss-jsp
 * @tags security
 *       external/cwe/cwe-079
 *       audit
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
import semmle.code.java.security.XSS
import semmle.code.java.frameworks.Servlets
import JSPLocations

module Xss {
  module XssConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

    predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }

    predicate isBarrier(DataFlow::Node node) { node instanceof XssSanitizer }

    predicate isBarrierOut(DataFlow::Node node) { node instanceof XssSinkBarrier }

    predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
      any(XssAdditionalTaintStep s).step(node1, node2)
    }
  }

  module XssFlow = TaintTracking::Global<XssConfig>;

  import XssFlow::PathGraph
}

// additional sources: Consider return values of ServletRequest methods to be tainted (potentially noisy)
class ServletRequestSource extends RemoteFlowSource {
  ServletRequestSource() {
    exists(Method m |
      this.asExpr().(MethodCall).getMethod() = m and
      m.getDeclaringType().getAnAncestor*().getQualifiedName() = "javax.servlet.ServletRequest"
    )
  }

  override string getSourceType() { result = "ServletRequest method return value" }
}

// Additional taint step: If an object is tainted, so are its methods' return values
class TaintedObjectMA extends XssAdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    node1.asExpr() = node2.asExpr().(MethodCall).getQualifier()
  }
}

// Additional taint step: If an argument to a constructor is tainted, so is the constructed object
class TaintedConstructorArg extends XssAdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    node1.asExpr() = node2.asExpr().(ConstructorCall).getAnArgument()
  }
}

bindingset[expr, varName]
predicate varAppearsInEvalExpr(string varName, string expr) {
  expr.regexpMatch(".*\\$\\{[^\\}]*\\b" + varName + "\\b[^\\}]*\\}.*")
}

string asLiteral(Expr expr) { result = expr.(StringLiteral).getValue() }

class EvalCall extends Call {
  int evalArgIdx;
  int ctxArgIdx;

  EvalCall() {
    exists(string name |
      name = this.getCallee().getName() and
      (
        name = "proprietaryEvaluate" and evalArgIdx = 0 and ctxArgIdx = 2
        or
        name = "createValueExpression" and evalArgIdx = 1 and ctxArgIdx = 0
      )
    )
  }

  string getEvalString() { result = asLiteral(this.getArgument(evalArgIdx)) }

  Expr getCtxExpr() { result = this.getArgument(ctxArgIdx) }
}

class AddAttrCall extends Call {
  AddAttrCall() { this.getCallee().getName() = ["addFlashAttribute", "addAttribute"] }

  string getAttrName() { result = asLiteral(this.getArgument(0)) }

  Expr getAttrValue() { result = this.getArgument(1) }
}

// Additional taint step: setting an attribute with a tainted value will make any
// evaluation of the argument in the context of a JSP also tainted
class JSPTaintStep extends XssAdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    exists(EvalCall propEval, AddAttrCall addAttr |
      varAppearsInEvalExpr(addAttr.getAttrName(), propEval.getEvalString()) and
      (
        exists(RedirectToJsp rtj | rtj.(ControlFlowNode).getAPredecessor*() = addAttr)
        implies
        propEval.getFile() =
          any(RedirectToJsp rtj | rtj.(ControlFlowNode).getAPredecessor*() = addAttr).getJspFile()
      )
    |
      node1.asExpr() = addAttr.getAttrValue() and
      node2.asExpr() = propEval
    )
  }
}

MethodCall methodCallOn(string methodName, Variable v) {
  result.getQualifier() = v.getAnAccess() and result.getCallee().getName() = methodName
}

// additional taint step to support JSP's "for each" constructs
class ForEachStep extends XssAdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Variable v, string varName, EvalCall eval |
      v.getType().getName() = "ForEachTag" and
      exists(DataFlow::Node ctxSrc |
        ContextFlow::ContextFlow::flow(ctxSrc,
          DataFlow2::exprNode(methodCallOn("setPageContext", v).getArgument(0))) and
        ContextFlow::ContextFlow::flow(ctxSrc, DataFlow2::exprNode(eval.getCtxExpr()))
        // config
        //     .hasFlow(ctxSrc, DataFlow2::exprNode(methodCallOn("setPageContext", v).getArgument(0))) and
        // config.hasFlow(ctxSrc, DataFlow2::exprNode(eval.getCtxExpr()))
      ) and
      node1.asExpr() = methodCallOn("setItems", v).getArgument(0) and
      node2.asExpr() = eval and
      varName = asLiteral(methodCallOn("setVar", v).getArgument(0)) and
      varAppearsInEvalExpr(varName, eval.getEvalString())
    )
  }
}

module LiteralConfig {
  module LiteralConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source.asExpr() instanceof StringLiteral }

    predicate isSink(DataFlow::Node sink) { exists(ReturnStmt rs | rs.getResult() = sink.asExpr()) }
  }

  module LiteralFlow = TaintTracking::Global<LiteralConfig>;
}

module ContextFlow {
  module ContextFlowConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
      source.asExpr().getType().getName() = "PageContext"
    }

    predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof Argument }
  }

  module ContextFlow = TaintTracking::Global<ContextFlowConfig>;
}

class RedirectToJsp extends ReturnStmt {
  File jsp;

  RedirectToJsp() {
    exists(DataFlow2::Node strLit, DataFlow2::Node retVal |
      strLit.asExpr().(StringLiteral).getValue().splitAt("/") + "_jsp.java" = jsp.getBaseName()
    |
      retVal.asExpr() = this.getResult() and LiteralConfig::LiteralFlow::flow(strLit, retVal)
    )
  }

  File getJspFile() { result = jsp }
}

import Xss::XssFlow::PathGraph

from Xss::XssFlow::PathNode source, Xss::XssFlow::PathNode sink, JSPTaintStep jspts
where
  Xss::XssFlow::flowPath(source, sink) and
  jspts.step(source.getNode(), sink.getNode())
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to $@.",
  source.getNode(), "user-provided value"
