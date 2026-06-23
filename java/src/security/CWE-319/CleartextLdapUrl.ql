/**
 * @name Cleartext LDAP URL
 * @description Configuring an LDAP context source with an `ldap://` URL transmits
 *              bind credentials and directory data over an unencrypted channel,
 *              allowing them to be intercepted. Use `ldaps://` or STARTTLS instead.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id githubsecuritylab/java/cleartext-ldap-url
 * @tags security
 *       external/cwe/cwe-319
 */

import java

/**
 * Holds if `e` evaluates to the constant string `v`, resolving a single field
 * indirection (e.g. a `private static final String` constant).
 */
predicate constantStringValue(Expr e, string v) {
  v = e.(CompileTimeConstantExpr).getStringValue()
  or
  exists(Variable var |
    e = var.getAnAccess() and
    v = var.getAnAssignedValue().(CompileTimeConstantExpr).getStringValue()
  )
}

/** A call that configures the URL of an LDAP/JNDI context source. */
class LdapUrlSink extends MethodCall {
  Expr urlArg;

  LdapUrlSink() {
    this.getMethod().hasName(["setUrl", "setUrls", "setProviderUrl"]) and
    this.getQualifier().getType().(RefType).getName().matches("%ContextSource%") and
    urlArg = this.getArgument(0)
  }

  Expr getUrlArg() { result = urlArg }
}

from LdapUrlSink sink, string url
where
  constantStringValue(sink.getUrlArg(), url) and
  url.regexpMatch("(?i)ldap://.*")
select sink, "LDAP context configured with cleartext URL '" + url + "'; use ldaps:// or STARTTLS."
