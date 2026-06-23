/**
 * @name JDBC connection disables TLS certificate validation
 * @description A JDBC URL containing `trustServerCertificate=true` makes the driver
 *              accept any server certificate. Even with `encrypt=true` the channel
 *              is then encrypted but unauthenticated, letting a man-in-the-middle
 *              impersonate the database.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id githubsecuritylab/java/jdbc-insecure-certificate
 * @tags security
 *       external/cwe/cwe-295
 */

import java

/**
 * Holds if `e` evaluates to the constant string `v`, resolving a single field
 * indirection and constant string concatenation.
 */
predicate constantStringValue(Expr e, string v) {
  v = e.(CompileTimeConstantExpr).getStringValue()
  or
  exists(Variable var |
    e = var.getAnAccess() and
    v = var.getAnAssignedValue().(CompileTimeConstantExpr).getStringValue()
  )
}

/** A call that opens or configures a JDBC connection from a URL argument. */
class JdbcUrlSink extends MethodCall {
  Expr urlArg;

  JdbcUrlSink() {
    this.getMethod().hasName("getConnection") and
    this.getMethod().getDeclaringType().hasQualifiedName("java.sql", "DriverManager") and
    urlArg = this.getArgument(0)
    or
    this.getMethod().hasName(["setUrl", "setJdbcUrl"]) and
    this.getQualifier().getType().(RefType).getName().matches(["%DataSource%", "%Config%"]) and
    urlArg = this.getArgument(0)
  }

  Expr getUrlArg() { result = urlArg }
}

from JdbcUrlSink sink, string url
where
  constantStringValue(sink.getUrlArg(), url) and
  url.regexpMatch("(?i).*trustservercertificate\\s*=\\s*true.*")
select sink,
  "JDBC connection uses 'trustServerCertificate=true', disabling certificate validation (MITM risk)."
