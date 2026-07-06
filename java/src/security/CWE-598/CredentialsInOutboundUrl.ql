/**
 * @name Credentials transmitted in outbound request URL
 * @description Embedding a password or secret in the URL of an outbound HTTP
 *              request exposes the credential in server logs, proxies and
 *              browser history, and over `http://` leaks it in cleartext on the
 *              wire. Send credentials in headers or a request body over TLS.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id githubsecuritylab/java/credentials-in-outbound-url
 * @tags security
 *       external/cwe/cwe-598
 *       external/cwe/cwe-319
 */

import java
import semmle.code.java.dataflow.TaintTracking
import CredentialsInUrlFlow::PathGraph

/** A getter whose name suggests it returns a credential or secret. */
class CredentialGetter extends MethodCall {
  CredentialGetter() {
    this.getMethod()
        .getName()
        .regexpMatch("(?i)get(pass(word|wd)?|secret|credential|apikey|api_?key|token).*")
  }
}

/** The URL argument of an outbound HTTP client request. */
class OutboundUrlArg extends Expr {
  OutboundUrlArg() {
    exists(MethodCall ma |
      ma.getMethod()
          .hasName([
              "getForObject", "getForEntity", "postForObject", "postForEntity", "postForLocation",
              "put", "delete", "patchForObject", "exchange", "execute"
            ]) and
      (
        ma.getMethod()
            .getDeclaringType()
            .getASupertype*()
            .hasQualifiedName("org.springframework.web.client", "RestOperations")
        or
        ma.getQualifier().getType().(RefType).getName().matches("%RestTemplate%")
      ) and
      this = ma.getArgument(0) and
      this.getType() instanceof TypeString
    )
  }
}

module CredentialsInUrlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CredentialGetter }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof OutboundUrlArg }
}

module CredentialsInUrlFlow = TaintTracking::Global<CredentialsInUrlConfig>;

from CredentialsInUrlFlow::PathNode source, CredentialsInUrlFlow::PathNode sink
where CredentialsInUrlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Credential from $@ is concatenated into the URL of an outbound HTTP request.", source.getNode(),
  "this getter"
