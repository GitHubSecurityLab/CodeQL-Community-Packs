/**
 * @name Rhino Script Injection
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id githubsecuritylab/rhino-script-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.dataflow.FlowSources
import RhinoInjectionFlow::PathGraph

class RhinoContextType extends Class {
  RhinoContextType() { hasQualifiedName("org.mozilla.javascript", "Context") }
}

class CompileMethod extends Method {
  CompileMethod() {
    this.getDeclaringType() instanceof RhinoContextType and
    this.hasName(["compileFunction", "compileReader"])
  }
}

class EvaluateMethod extends Method {
  EvaluateMethod() {
    this.getDeclaringType() instanceof RhinoContextType and
    this.hasName(["evaluateString", "evaluateReader"])
  }
}

class CompileScriptMethod extends Method {
  CompileScriptMethod() {
    this.getDeclaringType() instanceof RhinoContextType and
    this.hasName("compileScript")
  }
}

class RhinoInjectionSink extends DataFlow::ExprNode {
  RhinoInjectionSink() {
    exists(MethodAccess ma |
      (ma.getMethod() instanceof CompileMethod or ma.getMethod() instanceof EvaluateMethod) and
      this.getExpr() = ma.getArgument(1)
      or
      ma.getMethod() instanceof CompileScriptMethod and
      this.getExpr() = ma.getArgument(0)
    )
  }
}

private module RhinoInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof RhinoInjectionSink }
}

module RhinoInjectionFlow = TaintTracking::Global<RhinoInjectionConfig>;

from RhinoInjectionFlow::PathNode source, RhinoInjectionFlow::PathNode sink
where RhinoInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Rhino script injection from $@.", source.getNode(),
  "this user input"
