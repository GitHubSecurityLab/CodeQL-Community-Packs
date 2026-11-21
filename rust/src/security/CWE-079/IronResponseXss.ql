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
 * Tracks a parsed string literal to the tuple elements it becomes, through `unwrap`, `expect`, `?`
 * and local variables.
 */
module ParsedLiteralConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node.asExpr() instanceof ParsedStringLiteral }

  predicate isSink(DataFlow::Node node) {
    exists(TupleExpr modifiers | node.asExpr() = modifiers.getAField())
  }

  predicate isBarrier(DataFlow::Node barrier) { none() }
}

module ParsedLiteralFlow = TaintTracking::Global<ParsedLiteralConfig>;

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
      not exists(
        ParsedStringLiteral literal, DataFlow::ExprNode literalNode, DataFlow::ExprNode modifierNode
      |
        not isMarkupContentType(literal) and
        literalNode.asExpr() = literal and
        modifierNode.asExpr() = modifiers.getAField() and
        ParsedLiteralFlow::flow(literalNode, modifierNode)
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
