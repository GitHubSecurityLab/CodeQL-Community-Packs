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
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
import semmle.code.java.security.XSS
import JSPLocations

module Xss {
  module XssConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

    predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }

    predicate isBarrier(DataFlow::Node node) { node instanceof XssSanitizer }

    predicate isBarrierOut(DataFlow::Node node) { node instanceof XssSinkBarrier }

    predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
      exists(XssAdditionalTaintStep s | s.step(node1, node2))
    }
  }

  module XssFlow = TaintTracking::Global<XssConfig>;

  import XssFlow::PathGraph
}

class JSPTaintStep extends XssAdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Call propEval, Call addAttr, StringLiteral key |
      propEval.getCallee().getName() = "proprietaryEvaluate" and
      addAttr.getCallee().getName() = ["addFlashAttribute", "addAttribute"] and
      addAttr.getArgument(0) = key and
      propEval
          .getArgument(0)
          .(StringLiteral)
          .getValue()
          .regexpMatch(".*\\$\\{" + key.getValue() + "\\}.*") and
      (
        exists(RedirectToJsp rtj | rtj.(ControlFlowNode).getAPredecessor*() = addAttr)
        implies
        propEval.getFile() =
          any(RedirectToJsp rtj | rtj.(ControlFlowNode).getAPredecessor*() = addAttr).getJspFile()
      )
    |
      node1.asExpr() = addAttr.getArgument(1) and
      node2.asExpr() = propEval
    )
  }
}

module LiteralConfig {
  module LiteralConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source.asExpr() instanceof StringLiteral }

    predicate isSink(DataFlow::Node sink) { exists(ReturnStmt rs | rs.getResult() = sink.asExpr()) }
  }

  module LiteralFlow = TaintTracking::Global<LiteralConfig>;

  import LiteralFlow::PathGraph
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

from Xss::XssFlow::PathNode source, Xss::XssFlow::PathNode sink, JSPTaintStep jspts
where
  Xss::XssFlow::flowPath(source, sink) and
  jspts.step(source.getNode(), sink.getNode())
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to $@.",
  source.getNode(), "user-provided value"
