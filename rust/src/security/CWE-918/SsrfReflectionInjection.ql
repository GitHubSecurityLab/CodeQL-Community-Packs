/**
 * @name Server-side request forgery (extended framework coverage)
 * @description Making a network request with a URL whose host is derived from
 *              user-controlled data allows an attacker to make the server send
 *              requests to arbitrary (including internal) destinations.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision medium
 * @id githubsecuritylab/rust/ssrf-reflection-injection
 * @tags security
 *       experimental
 *       external/cwe/cwe-918
 */

private import rust
private import codeql.rust.controlflow.ControlFlowGraph
private import codeql.rust.dataflow.DataFlow
private import codeql.rust.dataflow.Ssa
private import codeql.rust.dataflow.TaintTracking
private import codeql.rust.security.RequestForgeryExtensions

/**
 * A read of an attacker-controlled field of an inbound `iron` HTTP request,
 * such as `req.url` (whose authority comes from the `Host` header),
 * `req.headers` or `req.body`.
 */
class IronRequestFieldSource extends RequestForgery::Source {
  IronRequestFieldSource() {
    exists(Struct s, string name |
      s.getCanonicalPath() = "iron::request::Request" and
      name = ["url", "headers", "body"] and
      this.asExpr().(FieldExpr).getStructField() = s.getStructField(name)
    )
  }
}

/**
 * Holds if `template` is the string literal of a format template that starts
 * with a fixed scheme and host, followed by a path, query or fragment
 * separator, for example `"https://my.app/{}"`. Values interpolated into such
 * a template cannot change the destination host of the request.
 */
bindingset[template]
private predicate isFixedHostTemplate(string template) {
  template.regexpMatch("(?s)r?#*\"[a-zA-Z][a-zA-Z0-9+.\\-]*://[^/{}?#@\\s\"\\\\]+[/?#].*")
}

/**
 * A `format!(...)` call whose template starts with a fixed scheme and host,
 * which is considered to sanitize request forgery.
 */
class FixedHostFormatBarrier extends RequestForgery::Barrier {
  FixedHostFormatBarrier() {
    exists(MacroExpr me, FormatArgsExpr fa |
      this.asExpr() = me and
      me.getMacroCall().getPath().getText() = "format" and
      fa.getParentNode+() = me and
      not exists(MacroExpr nested |
        nested != me and
        nested.getMacroCall().getPath().getText() = "format" and
        fa.getParentNode+() = nested and
        nested.getParentNode+() = me
      ) and
      isFixedHostTemplate(fa.getTemplate().(LiteralExpr).getTextValue())
    )
  }
}

/**
 * Holds if the variable `v` is read in an `async` block that does not declare it.
 */
private predicate isCapturedByAsyncBlock(Variable v) {
  exists(BlockExpr b, VariableReadAccess read |
    b.isAsync() and
    read = v.getAnAccess() and
    read.getParentNode+() = b and
    not v.getPat().getParentNode+() = b
  )
}

/** Holds if the control flow node `n` assigns to the variable `v`. */
private predicate assignsTo(CfgNode n, Variable v) {
  exists(VariableWriteAccess write | write.getVariable() = v |
    n.getAstNode() = write or n.getAstNode() = write.getAssignmentExpr()
  )
}

/**
 * Holds if the value that `source` gives to the variable `v` can still be its value at the control
 * flow node `n`. The `source` is the pattern that declares `v`, or an assignment to `v`, and no
 * other assignment to `v` lies on the path from it to `n`.
 */
private predicate valueLiveAt(Variable v, AstNode source, CfgNode n) {
  isCapturedByAsyncBlock(v) and
  (
    source = v.getPat()
    or
    source = any(VariableWriteAccess write | write.getVariable() = v).getAssignmentExpr()
  ) and
  n.getAstNode() = source
  or
  exists(CfgNode pred |
    valueLiveAt(v, source, pred) and
    n = pred.getASuccessor() and
    not assignsTo(n, v)
  )
}

/**
 * Holds if a captured value from `node1` reaches a read by `node2` in an
 * `async` block, for example a closure parameter used in `async move { ... }`
 * (as with `warp` `Filter::then`), without being overwritten first.
 *
 * The captured value is the one that the variable has when the block is created: the pattern that
 * declares it, or the right-hand side of an assignment that is not overwritten before the block. When
 * the block is created in a closure that is nested in the scope of the variable, the pattern is used.
 */
private predicate asyncBlockCaptureStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(Variable v, VariableReadAccess va, BlockExpr b, Ssa::Definition def |
    b.isAsync() and
    va = v.getAnAccess() and
    node2.asExpr() = va and
    def.getARead() = va and
    def.getAnUltimateDefinition() instanceof Ssa::CapturedEntryDefinition and
    va.getParentNode+() = b and
    not v.getPat().getParentNode+() = b and
    (
      exists(CfgNode creation, AstNode source |
        creation.getAstNode() = b and
        valueLiveAt(v, source, creation) and
        (
          node1.asPat() = source
          or
          node1.asExpr() = source.(AssignmentExpr).getRhs()
        )
      )
      or
      b.getEnclosingCfgScope() != v.getEnclosingCfgScope() and
      node1.asPat() = v.getPat()
    )
  )
}

/**
 * A taint-tracking configuration for detecting request forgery vulnerabilities.
 */
module SsrfReflectionInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RequestForgery::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof RequestForgery::Sink }

  predicate isBarrier(DataFlow::Node barrier) { barrier instanceof RequestForgery::Barrier }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    asyncBlockCaptureStep(node1, node2)
  }
}

module SsrfReflectionInjectionFlow = TaintTracking::Global<SsrfReflectionInjectionConfig>;

import SsrfReflectionInjectionFlow::PathGraph

from SsrfReflectionInjectionFlow::PathNode source, SsrfReflectionInjectionFlow::PathNode sink
where SsrfReflectionInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "The URL of this request depends on a $@.", source.getNode(),
  "user-provided value"
