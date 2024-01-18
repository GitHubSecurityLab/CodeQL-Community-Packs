/**
 * @name Command built from user-controlled sources
 * @description Building a system command from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id githubsecuritylab/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import go
import semmle.go.security.CommandInjection
import semmle.go.security.FlowSources

module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(UntrustedFlowSource source, Function function, DataFlow::CallNode callNode |
      source.asExpr() = node.asExpr() and
      source.(DataFlow::ExprNode).asExpr().getEnclosingFunction() = function.getFuncDecl() and
      (
        // function is called directly
        callNode.getACallee() = function.getFuncDecl()
        or
        // function is passed to another function to be called
        callNode.getCall().getAnArgument().(Ident).refersTo(function) //NEW with 2.13.2: or c.getASyntacticArgument().asExpr().(Ident).refersTo(f)
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjection::Sink s | sink = s | not s.doubleDashIsSanitizing())
  }
}

module Flow = TaintTracking::Global<FlowConfig>;

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This command depends on a $@.", source.getNode(),
  "user-provided value"
