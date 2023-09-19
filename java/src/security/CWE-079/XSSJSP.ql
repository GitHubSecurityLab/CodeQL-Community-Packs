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
import DataFlow::PathGraph
import JSPLocations

class XSSConfig extends TaintTracking::Configuration {
  XSSConfig() { this = "XSSConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof XssSanitizer }

  override predicate isSanitizerOut(DataFlow::Node node) { node instanceof XssSinkBarrier }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(XssAdditionalTaintStep s).step(node1, node2)
  }
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

class LiteralConfig extends TaintTracking2::Configuration {
  LiteralConfig() { this = "LiteralConfig" }

  override predicate isSource(DataFlow2::Node source) { source.asExpr() instanceof StringLiteral }

  override predicate isSink(DataFlow2::Node sink) {
    exists(ReturnStmt rs | rs.getResult() = sink.asExpr())
  }
}

class RedirectToJsp extends ReturnStmt {
  File jsp;

  RedirectToJsp() {
    exists(DataFlow2::Node strLit, DataFlow2::Node retVal, LiteralConfig lc |
      strLit.asExpr().(StringLiteral).getValue().splitAt("/") + "_jsp.java" = jsp.getBaseName()
    |
      retVal.asExpr() = this.getResult() and lc.hasFlow(strLit, retVal)
    )
  }

  File getJspFile() { result = jsp }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, XSSConfig conf, JSPExpr jspe
where conf.hasFlowPath(source, sink) and jspe.isClosest(sink.getNode().asExpr())
select jspe, source, sink, "Cross-site scripting vulnerability due to $@.", source.getNode(),
  "user-provided value"
