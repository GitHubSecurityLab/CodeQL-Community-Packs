import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2

abstract class SensitiveInformationSources extends DataFlow::Node { }

class HttpSession extends SensitiveInformationSources {
  HttpSession() {
    exists(MethodAccess ma |
      // https://docs.oracle.com/javaee/5/api/javax/servlet/http/HttpSession.html
      // Assumption: Nothing from the Session object should be logged
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpSession") and
      this.asExpr() = ma
    )
  }
}

class Properties extends SensitiveInformationSources {
  Properties() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getProperty") and
      this.asExpr() = ma
    )
  }
}

class SensitiveVariables extends SensitiveInformationSources {
  SensitiveVariables() {
    exists(Variable v |
      (
        // User data
        v.getName().toLowerCase().regexpMatch(".*(username|passport|fingerprint|dob|ssi).*")
        or
        // Creds / Secrets / Tokens
        v.getName().toLowerCase().regexpMatch(".*(password|pwd|hash|secret|token|session).*")
        or
        // Card Numbers
        v.getName().toLowerCase().regexpMatch(".*(cardnumber|cvv|sortcode|accountnumber).*")
      ) and
      this.asExpr() = v.getAnAccess()
    )
  }
}
