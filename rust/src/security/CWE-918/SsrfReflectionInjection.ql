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
      // the template of this `format!` call, not the template of a macro call in its arguments
      not exists(FormatArgsExpr outer |
        outer != fa and
        outer.getParentNode+() = me and
        fa.getParentNode+() = outer
      ) and
      isFixedHostTemplate(fa.getTemplate().(LiteralExpr).getTextValue())
    )
  }
}

/**
 * Holds if the closure or `async` block `scope` reads the variable `v`, perhaps in a closure or an
 * `async` block that is nested in it, and does not declare `v`.
 */
private predicate capturesVariable(Variable v, AstNode scope) {
  (scope instanceof ClosureExpr or scope.(BlockExpr).isAsync()) and
  exists(VariableReadAccess read | read = v.getAnAccess() and read.getParentNode+() = scope) and
  not v.getPat().getParentNode+() = scope
}

/** Holds if the variable `v` is read in an `async` block that does not declare it. */
private predicate isCapturedByAsyncBlock(Variable v) {
  exists(BlockExpr b | b.isAsync() and capturesVariable(v, b))
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

/** Holds if `n` is the entry node of a scope: it has no AST node and no predecessor. */
private predicate isEntryNode(CfgNode n) {
  not exists(n.getAstNode()) and not exists(n.getAPredecessor())
}

/**
 * Holds if the value that `v` has when the closure or `async` block that contains the control flow
 * node `n` starts can still be its value at `n`: no assignment to `v` lies on a path from the start
 * of that closure or block to `n`.
 */
private predicate entryValueLiveAt(Variable v, CfgNode n) {
  isCapturedByAsyncBlock(v) and
  exists(CfgNode entry |
    isEntryNode(entry) and
    n = entry.getASuccessor() and
    capturesVariable(v, n.getScope()) and
    not assignsTo(n, v)
  )
  or
  exists(CfgNode pred |
    entryValueLiveAt(v, pred) and
    n = pred.getASuccessor() and
    not assignsTo(n, v)
  )
}

/**
 * Holds if the value that `source` gives to the variable `v` can be its value where the closure or
 * `async` block `c` is created. The `source` is the pattern that declares `v`, or an assignment to
 * `v`. It either reaches that point in the scope that creates `c`, or the closure or `async` block
 * that creates `c` captured it and does not overwrite it before `c` is created.
 */
private predicate valueAtCreation(Variable v, AstNode source, AstNode c) {
  (c instanceof ClosureExpr or c.(BlockExpr).isAsync()) and
  exists(CfgNode creation | creation.getAstNode() = c |
    valueLiveAt(v, source, creation)
    or
    entryValueLiveAt(v, creation) and
    valueAtCreation(v, source, creation.getScope())
  )
}

/**
 * Holds if a captured value from `node1` reaches a read by `node2` in an
 * `async` block, for example a closure parameter used in `async move { ... }`
 * (as with `warp` `Filter::then`), without being overwritten first.
 *
 * The captured value is the one that the variable has when the closure or `async` block that contains
 * the read is created: the pattern that declares it, or the right-hand side of an assignment that is
 * not overwritten before that point. A closure or `async` block between the read and the declaration
 * passes on the value that it captured unless it assigns the variable first.
 */
private predicate asyncBlockCaptureStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(Variable v, VariableReadAccess va, BlockExpr b, Ssa::Definition def, AstNode source |
    b.isAsync() and
    va = v.getAnAccess() and
    node2.asExpr() = va and
    def.getARead() = va and
    def.getAnUltimateDefinition() instanceof Ssa::CapturedEntryDefinition and
    va.getParentNode+() = b and
    not v.getPat().getParentNode+() = b and
    valueAtCreation(v, source, va.getEnclosingCfgScope()) and
    (
      node1.asPat() = source
      or
      node1.asExpr() = source.(AssignmentExpr).getRhs()
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
