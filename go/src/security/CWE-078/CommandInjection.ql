/**
 * @name Command built from user-controlled sources
 * @description Building a system command from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id go/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import go
import semmle.go.security.CommandInjection
import DataFlow::PathGraph
import semmle.go.security.FlowSources

//Override CommandInjection::Configuration to use the in-use sources
class InUseCommandInjectionConfiguration extends CommandInjection::Configuration {
  override predicate isSource(DataFlow::Node node) {
    exists(UntrustedFlowSource source, Function function, DataFlow::CallNode callNode |
      source.asExpr() = node.asExpr() and

      source.(DataFlow::ExprNode).asExpr().getEnclosingFunction() = function.getFuncDecl() and
      (
        // function is called directly
        callNode.getACallee() = function.getFuncDecl()
        
        // function is passed to another function to be called
        or callNode.getCall().getAnArgument().(Ident).refersTo(function) //NEW with 2.13.2: or c.getASyntacticArgument().asExpr().(Ident).refersTo(f)
      )      
    )
  }
}
 
 from InUseCommandInjectionConfiguration cfg, CommandInjection::DoubleDashSanitizingConfiguration cfg2, DataFlow::PathNode source, DataFlow::PathNode sink
 where (cfg.hasFlowPath(source, sink) or cfg2.hasFlowPath(source, sink))
 select sink.getNode(), source, sink, "This command depends on a $@.", source.getNode(), "user-provided value"
