import java
import semmle.code.java.dataflow.FlowSources

class FileReadAccess extends LocalUserInput {
  FileReadAccess() {
    exists(MethodAccess ma |
      // https://docs.oracle.com/javase/8/docs/api/java/lang/Class.html#getResourceAsStream-java.lang.String-
      (
        ma.getMethod().hasQualifiedName("java.lang", "Class", "getResourceAsStream") or
        ma.getMethod().hasQualifiedName("java.lang", "ClassLoader", "getResourceAsStream") or
        // Finds any method that has the name "getResourceAsStream"
        ma.getMethod().hasQualifiedName(_, _, "getResourceAsStream")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}
