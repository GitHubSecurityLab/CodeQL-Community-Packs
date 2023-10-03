import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2

abstract class LoggingMethodsSinks extends DataFlow::Node { }

// TODO: Use the exists libs in CodeQL to extend this
class PrintMethods extends LoggingMethodsSinks {
  PrintMethods() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.io", _) and
      (
        ma.getMethod().hasName("println") or
        ma.getMethod().hasName("print") or
        ma.getMethod().getName() = "append" or
        ma.getMethod().getName() = "format" or
        ma.getMethod().getName() = "write"
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

// Ref :: https://github.com/github/codeql/blob/main/java/ql/src/experimental/Security/CWE/CWE-532/SensitiveInfoLog.ql
// Ref :: https://github.com/github/codeql/blob/main/java/ql/src/experimental/semmle/code/java/Logging.qll#L34
abstract class LoggerType extends RefType { }

class StandardLoggersType extends LoggerType {
  StandardLoggersType() {
    // JBoss Logging (`org.jboss.logging.Logger` in some implementations like JBoss Application Server 4.0.4 did not implement `BasicLogger`)
    this.hasQualifiedName("org.jboss.logging", ["BasicLogger", "Logger"]) or
    this.hasQualifiedName("org.slf4j.spi", "LoggingEventBuilder") or
    this.hasQualifiedName("org.slf4j", "Logger") or
    this.hasQualifiedName("org.scijava.log", "Logger") or
    this.hasQualifiedName("com.google.common.flogger", "LoggingApi") or
    this.hasQualifiedName("java.lang", "System$Logger") or
    this.hasQualifiedName("java.util.logging", "Logger") or
    this.hasQualifiedName("android.util", "Log")
  }
}

class Log4jLoggerType extends LoggerType {
  Log4jLoggerType() {
    this.hasQualifiedName("org.apache.log4j", "Category") or // Log4j 1
    this.hasQualifiedName("org.apache.logging.log4j", ["Logger", "LogBuilder"]) or // Log4j 2
    this.hasQualifiedName("org.apache.commons.logging", "Log")
  }
}

class LoggingMethods extends LoggingMethodsSinks {
  LoggingMethods() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType() instanceof LoggerType and
      (
        ma.getMethod().hasName("debug") or
        ma.getMethod().hasName("trace") or
        ma.getMethod().hasName("debugf") or
        ma.getMethod().hasName("debugv")
      ) and //Check low priority log levels which are more likely to be real issues to reduce false positives
      this.asExpr() = ma.getAnArgument()
    )
  }
}
