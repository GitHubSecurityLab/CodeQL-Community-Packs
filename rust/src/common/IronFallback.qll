/**
 * Provides a fallback that recognizes the `iron` crate by the names it uses, for databases in which
 * the calls into it cannot be resolved.
 *
 * A database that is built without compiling the code, as a code scanning default setup does
 * (`buildMode: none`), can leave every call that goes through a glob import of `iron::prelude` without
 * a target, such as `Iron::new`, `Response::with` and the methods of the request. The data extension
 * rows for Iron match canonical paths, and so do the sinks that are written as calls to a canonical
 * path, so none of them applies to such code. The classes and predicates here match the same API by
 * name, in files that use `iron`, and for calls that have no target.
 */

import rust
private import codeql.rust.dataflow.DataFlow

/** Gets the identifier of the first segment of `path`, such as `iron` for `iron::prelude`. */
private string getRootSegment(Path path) {
  not exists(path.getQualifier()) and result = path.getSegment().getIdentifier().getText()
  or
  result = getRootSegment(path.getQualifier())
}

/** Holds if `file` uses the `iron` crate, with a `use` item or an `extern crate` item. */
predicate isIronFile(File file) {
  exists(Use use |
    use.getLocation().getFile() = file and
    getRootSegment(use.getUseTree().getPath()) = "iron"
  )
  or
  exists(ExternCrate crate |
    crate.getLocation().getFile() = file and
    crate.getIdentifier().getText() = "iron"
  )
}

/** Holds if `typeRepr` is a type that is called `Request`, or a reference to one. */
private predicate isRequestType(TypeRepr typeRepr) {
  typeRepr.(PathTypeRepr).getPath().getSegment().getIdentifier().getText() = "Request"
  or
  isRequestType(typeRepr.(RefTypeRepr).getTypeRepr())
}

/**
 * A parameter of type `Request`, `&Request` or `&mut Request` of a function or closure in a file that
 * uses `iron`: the shape of an Iron handler or middleware, whether or not the type can be resolved.
 */
class IronRequestParameter extends DataFlow::Node {
  IronRequestParameter() {
    exists(Param param |
      param = this.asParameter() and
      isIronFile(param.getLocation().getFile()) and
      isRequestType(param.getTypeRepr())
    )
  }
}

/** The fields of an Iron request that hold data that the client controls. */
private predicate isRequestField(string name) { name = ["url", "headers", "body", "extensions"] }

/** Holds if the method called `name` only tells a property of its receiver, not its content. */
private predicate isNonRevealingMethod(string name) {
  name =
    [
      "len", "is_empty", "capacity", "count", "contains", "starts_with", "ends_with", "is_some",
      "is_none", "is_ok", "is_err"
    ]
}

/**
 * Holds if the flow goes from `pred` to `succ` in a file that uses `iron`, where the data flow library
 * cannot know it because the type of `pred` is not known: `succ` is the read of a field of the
 * request that does not resolve to a field, or the result of a method that has no target, called on
 * `pred`. A method with `escape` or `encode` in its name is taken to encode the value, the way the
 * standard queries take a call of a function with such a name, so it does not pass the value on.
 */
predicate ironUnresolvedStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(FieldExpr field |
    isIronFile(field.getLocation().getFile()) and
    isRequestField(field.getIdentifier().getText()) and
    not exists(field.getStructField()) and
    pred.asExpr() = field.getContainer() and
    succ.asExpr() = field
  )
  or
  exists(MethodCallExpr call |
    isIronFile(call.getLocation().getFile()) and
    not exists(call.getStaticTarget()) and
    not isNonRevealingMethod(call.getIdentifier().getText()) and
    not call.getIdentifier().getText().regexpMatch(".*(escape|encode).*") and
    pred.asExpr() = call.getReceiver() and
    succ.asExpr() = call
  )
}

/**
 * Holds if `call` is a call of `Response::with` in a file that uses `iron`, and the call has no target.
 * The call may name the type with a longer path, such as `iron::Response::with`.
 */
predicate isUnresolvedIronResponseWith(Call call) {
  isIronFile(call.getLocation().getFile()) and
  not exists(call.getStaticTarget()) and
  exists(Path path | path = call.(CallExpr).getFunction().(PathExpr).getPath() |
    path.getSegment().getIdentifier().getText() = "with" and
    path.getQualifier().getSegment().getIdentifier().getText() = "Response"
  )
}
