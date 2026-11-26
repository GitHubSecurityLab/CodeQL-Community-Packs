/**
 * @name Missing function level access control on a web method
 * @description A web method that changes data or performs an administrative action
 *              without an authorization check can be invoked by any caller.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id githubsecuritylab/cs/web/web-method-missing-access-control
 * @tags security
 *       experimental
 *       external/cwe/cwe-285
 *       external/cwe/cwe-284
 *       external/cwe/cwe-862
 */

import csharp
import semmle.code.csharp.security.auth.MissingFunctionLevelAccessControlQuery
import WebMethodActions

private ValueOrRefType getAnUnboundBaseType(ValueOrRefType t) {
  result = t.getABaseType().getUnboundDeclaration()
}

/**
 * Holds if `attr` is an MVC or Web API authorization filter. These filters run only in
 * their own pipelines, so they do not protect a web method.
 */
private predicate isPipelineAuthorizeAttribute(Attribute attr) {
  attr.getType()
      .getABaseType*()
      .hasFullyQualifiedName(["System.Web.Mvc", "System.Web.Http"], "AuthorizeAttribute")
}

/** Holds if `m` has an authorization attribute that applies to a web method. */
private predicate hasWebMethodAuthViaAttribute(WebMethodActionMethod m) {
  exists(Attribute attr |
    attr.getType().getABaseType*().getName().toLowerCase().matches("%auth%") and
    not isPipelineAuthorizeAttribute(attr)
  |
    attr = m.getOverridee*().getAnAttribute() or
    attr = getAnUnboundBaseType*(m.getDeclaringType()).getAnAttribute()
  )
}

from WebMethodActionMethod m
where
  needsAuth(m) and
  not hasAuthViaCode(m) and
  not hasAuthViaXml(m) and
  not hasWebMethodAuthViaAttribute(m) and
  exists(m.getBody().getAChildStmt()) // exclude empty methods
select m, "This web method is missing an authorization check."
