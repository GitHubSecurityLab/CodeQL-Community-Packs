/**
 * Provides a model of ASP.NET web methods (methods annotated with
 * `[System.Web.Services.WebMethod]`) as action methods for access control queries.
 */

import csharp
private import semmle.code.csharp.frameworks.system.web.Services
private import semmle.code.csharp.security.auth.ActionMethods

/**
 * A method annotated with `[System.Web.Services.WebMethod]`, which is remotely invocable
 * either as an ASMX web service operation or as an ASP.NET page method.
 */
class WebMethodActionMethod extends ActionMethod {
  WebMethodActionMethod() {
    this.getAnAttribute().getType() instanceof SystemWebServicesWebMethodAttributeClass
  }

  /**
   * Holds if this method may represent a stateful action. In addition to the generic
   * edit-like names, web methods whose names contain `transfer`, `withdraw`, `deposit`,
   * `update` or `remove` as a whole camelCase word are considered stateful.
   */
  override predicate isEdit() {
    super.isEdit()
    or
    this.getName()
        // separate camelCase words
        .regexpReplaceAll("([a-z])([A-Z])", "$1_$2")
        .regexpMatch("(?i)(.*_)?(transfer|withdraw|deposit|update|remove)(_.*)?")
  }
}
