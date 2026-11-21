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
 * Holds if a captured value from `node1` reaches a read by `node2` in an
 * `async` block, for example a closure parameter used in `async move { ... }`
 * (as with `warp` `Filter::then`), without being overwritten first.
 */
private predicate asyncBlockCaptureStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(Variable v, VariableAccess va, BlockExpr b, Ssa::Definition def |
    b.isAsync() and
    node1.asPat() = v.getPat() and
    va = v.getAnAccess() and
    va instanceof VariableReadAccess and
    node2.asExpr() = va and
    def.getARead() = va and
    def.getAnUltimateDefinition() instanceof Ssa::CapturedEntryDefinition and
    va.getParentNode+() = b and
    not v.getPat().getParentNode+() = b
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
