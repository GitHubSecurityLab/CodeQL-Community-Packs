/**
 * @name Code Injection
 * @description Code Injection may allow attackers to
 *              execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id githubsecuritylab/code-injection
 * @tags security
 *       external/cwe/cwe-94
 */

import java
import semmle.code.java.dataflow.FlowSources
import GroovyCodeInjectionFlow::PathGraph

class ParseClassMethod extends Method {
  ParseClassMethod() {
    this.getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName("groovy.lang", "GroovyClassLoader") and
    this.hasName("parseClass") and
    (
      this.getParameterType(0).(RefType).hasQualifiedName("java.lang", "String") or
      this.getParameterType(0).(RefType).hasQualifiedName("java.io", "InputStream") or
      this.getParameterType(0).(RefType).hasQualifiedName("java.io", "Reader")
    )
    or
    this.getDeclaringType().getASourceSupertype*().hasQualifiedName("groovy.lang", "GroovyShell") and
    (this.hasName("parse") or this.hasName("evaluate")) and
    (
      this.getParameterType(0).(RefType).hasQualifiedName("java.lang", "String") or
      this.getParameterType(0).(RefType).hasQualifiedName("java.io", "Reader")
    )
  }
}

class GroovyCodeInjectionSink extends DataFlow::ExprNode {
  GroovyCodeInjectionSink() {
    exists(MethodAccess ma |
      ma.getMethod() instanceof ParseClassMethod and
      this.getExpr() = ma.getArgument(0)
    )
  }
}

private module GroovyCodeInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof GroovyCodeInjectionSink }
}

module GroovyCodeInjectionFlow = TaintTracking::Global<GroovyCodeInjectionConfig>;

from GroovyCodeInjectionFlow::PathNode source, GroovyCodeInjectionFlow::PathNode sink
where GroovyCodeInjectionFlow::flowPath(source, sink)
select sink, source, sink, "Groovy code injection at $@.", sink.getNode(), "user input"
