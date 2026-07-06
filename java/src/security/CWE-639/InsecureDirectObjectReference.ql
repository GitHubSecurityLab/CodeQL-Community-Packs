/**
 * @name Insecure direct object reference
 * @description A web action that operates on a resource identified by user input,
 *              without checking that the current user is authorized to act on that
 *              specific resource, allows an attacker to access or modify arbitrary
 *              objects. This is the Java analogue of the C# query
 *              `cs/web/insecure-direct-object-reference`: it flags a state-changing
 *              Spring controller action that takes an id-like parameter but performs
 *              no user/session check and carries no method-security annotation.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id githubsecuritylab/java/insecure-direct-object-reference
 * @tags security
 *       external/cwe/cwe-639
 */

import java
import semmle.code.java.frameworks.spring.SpringController

/** A Spring MVC controller action method (the analogue of the C# `ActionMethod`). */
class ActionMethod extends SpringRequestMappingMethod {
  /** Gets a string describing this action: method name, class name, route, or HTTP verb. */
  string getADescription() {
    result =
      [this.getName(), this.getDeclaringType().getName(), this.getValue(), this.getMethodValue()]
  }

  /** Holds if this action may represent a state-changing operation. */
  predicate isEdit() {
    // Mapped with a state-changing HTTP verb.
    this.getMethodValue() = ["POST", "PUT", "DELETE", "PATCH"]
    or
    this.getAnAnnotation()
        .getType()
        .hasName(["PostMapping", "PutMapping", "DeleteMapping", "PatchMapping"])
    or
    // Or named/routed like a mutating action.
    exists(string str |
      str = this.getADescription().regexpReplaceAll("([a-z])([A-Z])", "$1_$2") and
      str.regexpMatch("(?i).*(edit|delete|modify|change|update|save|remove).*") and
      not str.regexpMatch("(?i).*(on_?change|changed).*")
    )
  }

  /** Holds if this action appears to be intended for admin users. */
  predicate isAdmin() {
    this.getADescription()
        .regexpReplaceAll("([a-z])([A-Z])", "$1_$2")
        .regexpMatch("(?i).*(admin|superuser).*")
  }
}

/**
 * Holds if `m` takes a request-bound parameter that looks like a resource id,
 * either by parameter name or by the explicit name in its binding annotation.
 */
predicate hasIdParameter(ActionMethod m) {
  exists(SpringRequestMappingParameter p | p = m.getARequestParameter() |
    p.getName().toLowerCase().matches(["%id", "%idx"])
    or
    exists(Annotation a | a = p.getAnAnnotation() |
      a.getType()
          .hasQualifiedName("org.springframework.web.bind.annotation",
            ["PathVariable", "RequestParam"]) and
      a.getStringValue(["value", "name"]).toLowerCase().matches(["%id", "%idx"])
    )
  )
}

/** Holds if `c`'s name suggests it checks the current user / session / resource owner. */
predicate authorizingCallable(Callable c) {
  exists(string name | name = c.getName().toLowerCase() |
    name.matches(["%user%", "%session%", "%principal%", "%owner%", "%current%"]) and
    not name.matches("%get%by%") // exclude getXById / getXByUsername style lookups
  )
}

private predicate calls(Callable c1, Callable c2) { c1.calls(c2) }

private predicate callsPlus(Callable c1, Callable c2) = fastTC(calls/2)(c1, c2)

/** Holds if `m` may, somewhere in its call graph, perform a check against the current user. */
predicate checksUser(ActionMethod m) {
  exists(Callable c | authorizingCallable(c) and callsPlus(m, c))
}

/**
 * Holds if `m`, its declaring type, or an overridden method carries a Spring
 * Security / JSR-250 method-security annotation that enforces authorization.
 */
predicate hasAuthorizationAnnotation(ActionMethod m) {
  exists(Annotation a |
    a.getType()
        .hasQualifiedName([
            "org.springframework.security.access.prepost",
            "org.springframework.security.access.annotation", "jakarta.annotation.security",
            "javax.annotation.security"
          ], ["PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "DenyAll"])
  |
    a = m.getAnAnnotation() or
    a = m.getAnOverride().getAnAnnotation() or
    a = m.getDeclaringType().getAnAnnotation()
  )
}

/**
 * Holds if `m` is a state-changing action keyed on a user-supplied id that
 * neither checks the current user nor declares a method-security annotation.
 */
predicate hasInsecureDirectObjectReference(ActionMethod m) {
  m.isEdit() and
  not m.isAdmin() and
  hasIdParameter(m) and
  not checksUser(m) and
  not hasAuthorizationAnnotation(m) and
  exists(m.getBody())
}

from ActionMethod m
where hasInsecureDirectObjectReference(m)
select m,
  "This action may be missing authorization checks to verify the current user is permitted to access the resource identified by the provided id."
