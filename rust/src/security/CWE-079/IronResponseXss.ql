/**
 * @name Cross-site scripting through an Iron response modifier tuple
 * @description Writing user input into the body of an Iron response built from a
 *              modifier tuple (for example `Response::with((status::Ok, body))`)
 *              allows for a cross-site scripting vulnerability, because Iron does
 *              not set a `Content-Type` and browsers sniff the body as HTML.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id githubsecuritylab/rust/iron-response-xss
 * @tags security
 *       experimental
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.security.XssExtensions

/**
 * A string literal that is parsed, such as the `"text/plain"` of
 * `"text/plain".parse::<Mime>().unwrap()`.
 */
private class ParsedStringLiteral extends StringLiteralExpr {
  ParsedStringLiteral() {
    exists(MethodCallExpr parse |
      parse.getIdentifier().getText() = "parse" and
      parse.getReceiver() = this
    )
  }
}

/** Holds if `literal` names a content type that browsers render as markup. */
private predicate isMarkupContentType(StringLiteralExpr literal) {
  literal.getTextValue().toLowerCase().matches(["%html%", "%xml%"])
}

/**
 * Holds if `e` is the value that parsing `literal` produces: the `parse` call itself, that call
 * unwrapped with `unwrap`, `expect` or `?`, or a local variable that holds such a value. A value
 * that is merely derived from it, for example by formatting it into a string, is not.
 */
private predicate isParsedFrom(Expr e, ParsedStringLiteral literal) {
  e.(MethodCallExpr).getIdentifier().getText() = "parse" and
  e.(MethodCallExpr).getReceiver() = literal
  or
  e.(MethodCallExpr).getIdentifier().getText() = ["unwrap", "expect"] and
  isParsedFrom(e.(MethodCallExpr).getReceiver(), literal)
  or
  isParsedFrom(e.(TryExpr).getExpr(), literal)
  or
  exists(DataFlow::ExprNode source, DataFlow::ExprNode target |
    target.asExpr() = e and
    source.asExpr() != e and
    DataFlow::localFlow(source, target) and
    isParsedFrom(source.asExpr(), literal)
  )
}

/**
 * Holds if `modifier` is a content type that is parsed from string literals, and every parsed literal
 * that reaches it names a content type that is not markup. A content type that can also be HTML or XML,
 * for example on one branch of an `if`, is not safe.
 */
private predicate isSafeContentType(Expr modifier) {
  exists(ParsedStringLiteral safe |
    isParsedFrom(modifier, safe) and
    not isMarkupContentType(safe)
  ) and
  not exists(ParsedStringLiteral markup |
    isParsedFrom(modifier, markup) and
    isMarkupContentType(markup)
  )
}

/**
 * An element of a modifier tuple passed to `iron::Response::with`, such as `body` in
 * `Response::with((status::Ok, body))`.
 *
 * Tuples that contain a content type modifier parsed from a string literal that does not name
 * HTML or XML set an explicit, safe `Content-Type` and are not considered sinks.
 */
class IronResponseModifierTupleElement extends DataFlow::Node {
  IronResponseModifierTupleElement() {
    exists(Call call, TupleExpr modifiers, Expr argument |
      call.getStaticTarget().getCanonicalPath() = "<iron::response::Response>::with" and
      argument = call.getPositionalArgument(0) and
      exists(DataFlow::ExprNode tupleNode, DataFlow::ExprNode argumentNode |
        tupleNode.asExpr() = modifiers and
        argumentNode.asExpr() = argument and
        DataFlow::localFlow(tupleNode, argumentNode)
      ) and
      this.asExpr() = modifiers.getAField() and
      not exists(Expr modifier |
        modifier = modifiers.getAField() and
        isSafeContentType(modifier)
      )
    )
  }
}

module IronResponseXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof Xss::Source }

  predicate isSink(DataFlow::Node node) { node instanceof IronResponseModifierTupleElement }

  predicate isBarrier(DataFlow::Node barrier) { barrier instanceof Xss::Barrier }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module IronResponseXssFlow = TaintTracking::Global<IronResponseXssConfig>;

import IronResponseXssFlow::PathGraph

from IronResponseXssFlow::PathNode sourceNode, IronResponseXssFlow::PathNode sinkNode
where IronResponseXssFlow::flowPath(sourceNode, sinkNode)
select sinkNode.getNode(), sourceNode, sinkNode, "Cross-site scripting vulnerability due to a $@.",
  sourceNode.getNode(), "user-provided value"
