/**
 * @name Unsafe URI Check
 * @description Checking a URL against an allow/block list in Java may be unsafe.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id githubsecuritylab/unsafe-uri-check
 * @tags security
 *       external/cwe/cwe-22
 */

import java
import semmle.code.java.dataflow.FlowSources
import UnsafeURICheckFlow::PathGraph

// Example: https://mail-archives.apache.org/mod_mbox/ambari-user/202102.mbox/%3CCAEJYuxEQZ_aPwJdAaSxPu-Dva%3Dhc7zZUx3-pzBORbd23g%2BGH1A%40mail.gmail.com%3E
class ServletFilterInterface extends Interface {
  ServletFilterInterface() { this.hasQualifiedName("javax.servlet", "Filter") }
}

class ContainerRequestFilterInterface extends Interface {
  ContainerRequestFilterInterface() {
    this.hasQualifiedName("javax.ws.rs.container", "ContainerRequestFilter")
  }
}

class ServletRequestInterface extends Interface {
  ServletRequestInterface() { this.hasQualifiedName("javax.servlet.http", "HttpServletRequest") }
}

class UriInfoType extends RefType {
  UriInfoType() { this.hasQualifiedName("javax.ws.rs.core", "UriInfo") }
}

abstract class FilterMethod extends Method { }

string getSecurityFilterRegexp() { result = ".*(auth|security|jwt|allow|block|login).*" }

class FilterContainerRequestFilterMethod extends FilterMethod {
  FilterContainerRequestFilterMethod() {
    exists(Method m |
      this.overrides*(m) and
      m.getName() = "filter" and
      m.getDeclaringType() instanceof ContainerRequestFilterInterface and
      this.getDeclaringType().getName().toLowerCase().regexpMatch(getSecurityFilterRegexp())
    )
  }
}

class DoFilterServletRequestMethod extends FilterMethod {
  DoFilterServletRequestMethod() {
    exists(Method m |
      this.overrides*(m) and
      m.getName() = "doFilter" and
      m.getDeclaringType() instanceof ServletFilterInterface and
      this.getDeclaringType().getName().toLowerCase().regexpMatch(getSecurityFilterRegexp())
    )
  }
}

abstract class GetUriPathCall extends MethodCall { }

class GetRequestURIMethodCall extends GetUriPathCall {
  GetRequestURIMethodCall() {
    this.getMethod().getName() = "getRequestURI" and
    this.getMethod().getDeclaringType() instanceof ServletRequestInterface
  }
}

class UriInfoGetPathMethodCall extends GetUriPathCall {
  UriInfoGetPathMethodCall() {
    this.getMethod().getName() = "getPath" and
    this.getMethod().getDeclaringType() instanceof UriInfoType
  }
}

private module UnsafeURICheckConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(GetUriPathCall call, FilterMethod m |
      source.asExpr() = call and
      (
        m.polyCalls*(call.getEnclosingCallable()) or
        m.polyCalls*(call.getEnclosingCallable().getEnclosingCallable()) or
        m.polyCalls*(call.getEnclosingCallable().getEnclosingCallable().getEnclosingCallable())
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall ma |
      // java.util.regex.Pattern.matcher("aaaaab");
      ma.getMethod().getName() = "matcher" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
      sink.asExpr() = ma.getArgument(0)
      or
      // java.util.regex.Pattern.matches("a*b", "aaaaab");
      ma.getMethod().getName() = "matches" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
      sink.asExpr() = ma.getArgument(1)
      or
      ma.getMethod().getName() = "matches" and
      ma.getMethod().getDeclaringType() instanceof TypeString and
      sink.asExpr() = ma.getQualifier()
      or
      ma.getMethod().getName() = ["contains", "startsWith", "endsWith"] and
      ma.getMethod().getDeclaringType() instanceof TypeString and
      not ma.getArgument(0).(CompileTimeConstantExpr).getStringValue() = "/" and
      sink.asExpr() = ma.getQualifier()
    )
  }
}

module UnsafeURICheckFlow = TaintTracking::Global<UnsafeURICheckConfig>;

from UnsafeURICheckFlow::PathNode source, UnsafeURICheckFlow::PathNode sink
where UnsafeURICheckFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe URI check"
