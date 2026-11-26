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
import common.IronFallback

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
 * Holds if `tuple` is a tuple expression whose value the expression `e` holds: `e` is the tuple, or a
 * local variable or expression that the tuple flows to.
 */
private predicate holdsTuple(Expr e, TupleExpr tuple) {
  exists(DataFlow::ExprNode tupleNode, DataFlow::ExprNode eNode |
    tupleNode.asExpr() = tuple and
    eNode.asExpr() = e and
    DataFlow::localFlow(tupleNode, eNode)
  )
}

/**
 * Gets a modifier of the response that is built from `e`, the argument of `Response::with`: an element
 * of the tuple that `e` holds, or of a tuple that is nested in it. Iron applies the modifiers of a
 * nested tuple to the same response.
 */
private Expr getAModifier(Expr e) {
  exists(TupleExpr tuple, Expr element | holdsTuple(e, tuple) and element = tuple.getAField() |
    result = element and not holdsTuple(element, _)
    or
    result = getAModifier(element)
  )
}

/**
 * Holds if the response that is built from `argument` has an explicit content type that is not markup:
 * a modifier is parsed from a string literal that does not name HTML or XML, and no modifier of the
 * response is parsed from a literal that does. Iron applies the modifiers in order, so a `text/html`
 * modifier after a `text/plain` one replaces it, and a response whose content type can be markup is
 * not safe. This also covers a content type that is parsed from different literals on different
 * branches of an `if`.
 */
private predicate hasSafeContentType(Expr argument) {
  exists(ParsedStringLiteral safe |
    isParsedFrom(getAModifier(argument), safe) and
    not isMarkupContentType(safe)
  ) and
  not exists(ParsedStringLiteral markup |
    isParsedFrom(getAModifier(argument), markup) and
    isMarkupContentType(markup)
  )
}

/**
 * An element of a modifier tuple passed to `iron::Response::with`, such as `body` in
 * `Response::with((status::Ok, body))`, or of a tuple that is nested in it.
 *
 * A call of `Response::with` that cannot be resolved is matched by its name in a file that uses `iron`
 * (see `common.IronFallback`).
 *
 * A response whose modifiers include a content type that is parsed from a string literal that does not
 * name HTML or XML, and none that does, has an explicit, safe `Content-Type` and is not considered a
 * sink.
 */
class IronResponseModifierTupleElement extends DataFlow::Node {
  IronResponseModifierTupleElement() {
    exists(Call call, Expr argument |
      (
        call.getStaticTarget().getCanonicalPath() = "<iron::response::Response>::with"
        or
        isUnresolvedIronResponseWith(call)
      ) and
      argument = call.getPositionalArgument(0) and
      this.asExpr() = getAModifier(argument) and
      not hasSafeContentType(argument)
    )
  }
}

/**
 * The argument of a call of `Response::with` that has no target, when it is a body on its own and not a
 * tuple of modifiers. A call that can be resolved is covered by the data extension row for the same
 * function, which the standard cross-site scripting query uses, and a body that is set on its own has no
 * content type.
 */
class IronUnresolvedResponseBody extends DataFlow::Node {
  IronUnresolvedResponseBody() {
    exists(Call call, Expr argument |
      isUnresolvedIronResponseWith(call) and
      argument = call.getPositionalArgument(0) and
      not holdsTuple(argument, _) and
      this.asExpr() = argument
    )
  }
}

/**
 * The argument of a call of `Response::with` that resolves, when it is a body on its own and not a tuple
 * of modifiers. The data extension row for the function makes it a sink of the standard cross-site
 * scripting query. This query reports a flow into it only when the standard query does not (see the
 * `where` clause): when the handler is not registered, so that the row has no source for it, or when a
 * call that has no target lies between the request and the body.
 */
class IronResolvedResponseBody extends DataFlow::Node {
  IronResolvedResponseBody() {
    exists(Call call, Expr argument |
      call.getStaticTarget().getCanonicalPath() = "<iron::response::Response>::with" and
      argument = call.getPositionalArgument(0) and
      not holdsTuple(argument, _) and
      this.asExpr() = argument
    )
  }
}

module IronResponseXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof Xss::Source or node instanceof IronRequestParameter
  }

  predicate isSink(DataFlow::Node node) {
    node instanceof IronResponseModifierTupleElement or
    node instanceof IronUnresolvedResponseBody or
    node instanceof IronResolvedResponseBody
  }

  predicate isBarrier(DataFlow::Node barrier) { barrier instanceof Xss::Barrier }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    ironUnresolvedStep(pred, succ)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module IronResponseXssFlow = TaintTracking::Global<IronResponseXssConfig>;

/**
 * The configuration of the standard cross-site scripting query (`rust/xss`), copied from it. It has none
 * of the steps of this query for calls that have no target, so a flow that it finds is a flow that the
 * standard query reports.
 */
module StandardXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof Xss::Source }

  predicate isSink(DataFlow::Node node) { node instanceof Xss::Sink }

  predicate isBarrier(DataFlow::Node barrier) { barrier instanceof Xss::Barrier }
}

module StandardXssFlow = TaintTracking::Global<StandardXssConfig>;

import IronResponseXssFlow::PathGraph

from IronResponseXssFlow::PathNode sourceNode, IronResponseXssFlow::PathNode sinkNode
where
  IronResponseXssFlow::flowPath(sourceNode, sinkNode) and
  // A handler that the data extension rows already make a source is reported through that source.
  not (
    sourceNode.getNode() instanceof IronRequestParameter and
    not sourceNode.getNode() instanceof Xss::Source and
    exists(IronResponseXssFlow::PathNode modelled |
      IronResponseXssFlow::flowPath(modelled, sinkNode) and
      modelled.getNode() instanceof Xss::Source
    )
  ) and
  // A body on its own that goes to a call that resolves is left to the standard query when its analysis
  // reaches the body from the same source. When a call that has no target lies in between, it does not,
  // and this query reports the flow.
  not (
    sinkNode.getNode() instanceof IronResolvedResponseBody and
    exists(DataFlow::Node standardSink |
      StandardXssFlow::flow(sourceNode.getNode(), standardSink) and
      standardSink.getLocation() = sinkNode.getNode().getLocation()
    )
  )
select sinkNode.getNode(), sourceNode, sinkNode, "Cross-site scripting vulnerability due to a $@.",
  sourceNode.getNode(), "user-provided value"
