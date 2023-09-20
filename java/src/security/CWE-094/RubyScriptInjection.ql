/**
 * @name Ruby Code Injection
 * @description Ruby Code Injection may allow attackers to
 *              execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id githubsecuritylab/ruby-code-injection
 * @tags security
 *       external/cwe/cwe-94
 */

import java
import semmle.code.java.dataflow.FlowSources
import RubyScriptInjectionFlow::PathGraph

class BSFSink extends DataFlow::ExprNode {
  BSFSink() {
    exists(MethodAccess ma, Method m | ma.getMethod() = m |
      m.getName() = ["exec", "eval", "compileScript", "compileExpr", "compileApply"] and
      m.getDeclaringType().hasQualifiedName("org.apache.bsf", "BSFManager") and
      this.getExpr() = ma.getAnArgument()
    )
  }
}

class JRubySink extends DataFlow::ExprNode {
  JRubySink() {
    exists(MethodAccess ma, Method m | ma.getMethod() = m |
      m.getName() = ["runScriptlet", "parse"] and
      m.getDeclaringType().hasQualifiedName("org.jruby.embed", "ScriptingContainer") and
      this.getExpr() = ma.getAnArgument()
      or
      m.getName() = ["eval", "parse"] and
      m.getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("org.jruby", "RubyRuntimeAdapter") and
      this.getExpr() = ma.getArgument(1)
    )
  }
}

private module RubyScriptInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof JRubySink or
    sink instanceof BSFSink
  }
}

module RubyScriptInjectionFlow = TaintTracking::Global<RubyScriptInjectionConfig>;

from RubyScriptInjectionFlow::PathNode source, RubyScriptInjectionFlow::PathNode sink
where RubyScriptInjectionFlow::flowPath(source, sink)
select sink, source, sink, "Ruby script injection at $@.", sink.getNode(), "user input"
