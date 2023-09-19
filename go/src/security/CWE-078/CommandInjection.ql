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
import semmle.go.security.CommandInjectionCustomizations::CommandInjection

//Override CommandInjection::Configuration to use the in-use sources
class InUseAsSource extends Source instanceof UntrustedFlowSource {
  InUseAsSource() {
    exists(UntrustedFlowSource source, Function function, DataFlow::CallNode callNode |
      source.asExpr() = this.asExpr() and
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
}

module Flow =
  DataFlow::MergePathGraph<CommandInjection::Flow::PathNode,
    CommandInjection::DoubleDashSanitizingFlow::PathNode, CommandInjection::Flow::PathGraph,
    CommandInjection::DoubleDashSanitizingFlow::PathGraph>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where
  CommandInjection::Flow::flowPath(source.asPathNode1(), sink.asPathNode1()) or
  CommandInjection::DoubleDashSanitizingFlow::flowPath(source.asPathNode2(), sink.asPathNode2())
select sink.getNode(), source, sink, "This command depends on a $@.", source.getNode(),
  "user-provided value"
