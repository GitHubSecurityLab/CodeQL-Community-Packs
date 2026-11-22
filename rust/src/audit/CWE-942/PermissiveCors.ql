/**
 * @name Permissive CORS configuration
 * @description Allowing any origin to read cross-origin responses lets an
 *              arbitrary website read data served to a victim's browser.
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.5
 * @sub-severity low
 * @precision very-low
 * @id githubsecuritylab/audit/rust/permissive-cors
 * @tags security
 *       experimental
 *       audit
 *       external/cwe/cwe-942
 */

import rust
import codeql.rust.dataflow.DataFlow

/** Holds if `e` is a string literal whose value is `value`. */
bindingset[value]
private predicate isStringLiteral(Expr e, string value) {
  e.(StringLiteralExpr).getTextValue() = "\"" + value + "\""
}

/**
 * Holds if `c` builds a header value from its argument, such as `HeaderValue::from_static("*")`.
 */
private predicate isHeaderValueConstructor(CallExpr c) {
  isPathCall(c, "HeaderValue",
    ["from_static", "from_str", "from_bytes", "from_maybe_shared", "try_from"])
  or
  isPathCall(c, "String", "from")
  or
  isPathCall(c, "AllowOrigin", "exact")
}

/**
 * Holds if the method `name` returns its receiver, or a conversion of it, without changing the value:
 * parsing, unwrapping and conversions. A method that changes the value, such as `replace`, is not
 * listed.
 */
private predicate isValuePreservingMethod(string name) {
  name =
    [
      "parse", "unwrap", "expect", "to_string", "to_owned", "into", "try_into", "clone", "as_str",
      "as_ref", "as_bytes", "to_vec", "ok", "map_err"
    ]
}

/**
 * Gets an expression that the value of `e` is taken from: the receiver of a value-preserving method
 * call, the argument of a constructor of a header value, a referenced or `?`-operand expression, or a
 * reaching assignment to a local variable read by `e`.
 *
 * This handles wrappers such as `"*".parse::<HeaderValue>().unwrap()`,
 * `HeaderValue::from_static("*")` and `let origin = "*"; ... origin`. Other arguments are not
 * followed: in `origin.parse::<HeaderValue>().expect("*")` the `"*"` is only a message. Other methods
 * are not followed either: `"*".replace("*", "https://trusted.example.com")` is not a wildcard.
 */
private Expr getAnInnerExpr(Expr e) {
  result = e.(MethodCallExpr).getReceiver() and
  isValuePreservingMethod(e.(MethodCallExpr).getIdentifier().getText())
  or
  isHeaderValueConstructor(e) and result = e.(CallExpr).getArgList().getAnArg()
  or
  result = e.(RefExpr).getExpr()
  or
  result = e.(TryExpr).getExpr()
  or
  exists(Variable v, DataFlow::ExprNode source, DataFlow::ExprNode target |
    e = v.getAnAccess() and
    target.asExpr() = e and
    source.asExpr() = result and
    source.asExpr() != e and
    DataFlow::localFlow(source, target)
  )
}

/** Holds if `p` is a path whose final segment is `name` (for example `Any` or `cors::Any`). */
bindingset[name]
private predicate pathEndsWith(Path p, string name) { p.getText() = name }

/**
 * Holds if `p` is a path whose final segment is `name` and whose qualifier
 * ends in `qualifier` (for example `CorsLayer::permissive`).
 */
bindingset[qualifier, name]
private predicate qualifiedPathEndsWith(Path p, string qualifier, string name) {
  p.getText() = name and
  p.getQualifier().getText() = qualifier
}

/** Holds if `c` is a call to a function at a path ending in `qualifier::name`. */
bindingset[qualifier, name]
private predicate isPathCall(CallExpr c, string qualifier, string name) {
  qualifiedPathEndsWith(c.getFunction().(PathExpr).getPath(), qualifier, name)
}

/** Holds if `e` is (or is derived from) a value denoting the wildcard CORS origin. */
private predicate isWildcardOriginValue(Expr e) {
  isStringLiteral(e, "*")
  or
  // `tower_http::cors::Any`, `salvo::cors::Any`
  pathEndsWith(e.(PathExpr).getPath(), "Any")
  or
  // `tower_http::cors::AllowOrigin::any()`, `AllowOrigin::mirror_request()`
  isPathCall(e, "AllowOrigin", ["any", "mirror_request"])
  or
  isWildcardOriginValue(getAnInnerExpr(e))
}

/**
 * Holds if `e` names the `Access-Control-Allow-Origin` header, either directly
 * or via a header-name constructor such as `HeaderName::from_static(...)`.
 */
private predicate isAllowOriginHeaderName(Expr e) {
  e.(StringLiteralExpr).getTextValue().toLowerCase() = "\"access-control-allow-origin\""
  or
  pathEndsWith(e.(PathExpr).getPath(), "ACCESS_CONTROL_ALLOW_ORIGIN")
  or
  isAllowOriginHeaderName(e.(RefExpr).getExpr())
  or
  exists(CallExpr c | c = e |
    isPathCall(c, "HeaderName", ["from_static", "from_lowercase", "from_bytes", "from_str"]) and
    isAllowOriginHeaderName(c.getArgList().getArg(0))
  )
  or
  exists(MethodCallExpr c |
    c = e and
    c.getIdentifier().getText() in ["unwrap", "expect"] and
    isAllowOriginHeaderName(c.getReceiver())
  )
  or
  isAllowOriginHeaderName(e.(TryExpr).getExpr())
}

/**
 * Holds if `call` sets a header on a response, a header map or a header layer: `insert`, `append`
 * and `header` style methods, and functions such as `Header::new` and `warp::reply::with::header`.
 * A call that only receives a header name and a value, such as a comparison helper, does not.
 */
private predicate isHeaderWriter(Expr call) {
  call.(MethodCallExpr).getIdentifier().getText() =
    ["insert", "append", "header", "insert_header", "append_header", "add_header", "set_header"]
  or
  call.(CallExpr).getFunction().(PathExpr).getPath().getText() =
    ["header", "with_header", "overriding", "if_not_present", "appending"]
  or
  isPathCall(call, "Header", "new")
}

/**
 * Holds if `name` and `value` are an adjacent header name/value pair, either
 * consecutive arguments of a call that sets a header (for example
 * `headers.insert(name, value)` or `with_header(reply, name, value)`) or a
 * 2-tuple `(name, value)`.
 */
private predicate isHeaderPair(Expr pair, Expr name, Expr value) {
  isHeaderWriter(pair) and
  exists(ArgList args, int i |
    args = pair.(MethodCallExpr).getArgList() or args = pair.(CallExpr).getArgList()
  |
    name = args.getArg(i) and
    value = args.getArg(i + 1)
  )
  or
  pair.(TupleExpr).getNumberOfFields() = 2 and
  name = pair.(TupleExpr).getField(0) and
  value = pair.(TupleExpr).getField(1)
}

/**
 * Holds if `e` configures a CORS policy (or sets a CORS response header) that
 * allows any origin, described by `description`.
 */
predicate isPermissiveCors(Expr e, string description) {
  // warp: `warp::cors().allow_any_origin()`; actix-cors: `Cors::default().allow_any_origin()`
  e.(MethodCallExpr).getIdentifier().getText() = "allow_any_origin" and
  e.(MethodCallExpr).getArgList().getNumberOfArgs() = 0 and
  description = "This CORS policy allows any origin"
  or
  // tower-http / salvo: `.allow_origin(Any)`, `.allow_origin("*".parse().unwrap())`
  e.(MethodCallExpr).getIdentifier().getText() = "allow_origin" and
  isWildcardOriginValue(e.(MethodCallExpr).getArgList().getArg(0)) and
  description = "This CORS policy allows any origin"
  or
  // actix-cors: `Cors::permissive()`; tower-http: `CorsLayer::permissive()` / `very_permissive()`
  (
    isPathCall(e, "Cors", "permissive")
    or
    isPathCall(e, "CorsLayer", ["permissive", "very_permissive"])
    or
    // rocket_cors: `AllowedOrigins::all()`
    isPathCall(e, "AllowedOrigins", "all")
  ) and
  description = "This CORS policy allows any origin"
  or
  // iron / hyper 0.10: `AccessControlAllowOrigin::Any`
  qualifiedPathEndsWith(e.(PathExpr).getPath(), "AccessControlAllowOrigin", "Any") and
  description = "This Access-Control-Allow-Origin header allows any origin"
  or
  // raw header: `headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, "*")`, `("Access-Control-Allow-Origin", "*")`
  exists(Expr name, Expr value |
    isHeaderPair(e, name, value) and
    isAllowOriginHeaderName(name) and
    isWildcardOriginValue(value)
  ) and
  description = "This Access-Control-Allow-Origin header allows any origin"
}

from Expr e, string description
where isPermissiveCors(e, description)
select e,
  description +
    ". Review whether the responses of this service contain sensitive or credentialed data."
