import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSteps
import semmle.code.java.dataflow.ExternalFlow

/**
 * Taintsteps to enable this -> read flow
 * eg: this.field
 */
class FieldReadTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(FieldRead fa |
      n1 = DataFlow::getFieldQualifier(fa) and
      n2.asExpr() = fa
    )
  }
}

/**
 * Treats a field write as a jump step (one that discards calling context, and supposes that probably at some point a read step takes place)
 */
class FieldTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    // From field write to read
    exists(Field f, RefType t |
      n1.asExpr() = f.getAnAssignedValue() and
      n2.asExpr() = f.getAnAccess() and
      n1.asExpr().getEnclosingCallable().getDeclaringType() = t and
      n2.asExpr().getEnclosingCallable().getDeclaringType() = t
    )
  }
}

/**
 * Create jump steps for methods connected by the wait/notify pattern
 */
class NotifyWaitTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(
      MethodAccess notify, RefType t, MethodAccess wait, SynchronizedStmt notifySync,
      SynchronizedStmt waitSync
    |
      notify.getMethod().getName() = ["notify", "notifyAll"] and
      notify.getAnEnclosingStmt() = notifySync and
      notifySync.getExpr().getType() = t and
      wait.getMethod().getName() = "wait" and
      wait.getAnEnclosingStmt() = waitSync and
      waitSync.getExpr().getType() = t and
      exists(AssignExpr write, FieldAccess read, Field f |
        write.getAnEnclosingStmt() = notifySync and
        write.getDest().(FieldAccess).getField() = f and
        write = n1.asExpr() and
        read.getAnEnclosingStmt() = waitSync and
        read.getField() = f and
        read = n2.asExpr()
      )
    )
  }
}

/**
 * Convey taint from the argument of a method call that can throw an exception
 * to the exception variable in the correspondinf catch block
 */
class ExceptionTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(Call call, TryStmt t, CatchClause c, MethodAccess gm |
      call.getEnclosingStmt().getEnclosingStmt*() = t.getBlock() and
      t.getACatchClause() = c and
      (
        call.getCallee().getAThrownExceptionType().getASubtype*() = c.getACaughtType() or
        c.getACaughtType().getASupertype*() instanceof TypeRuntimeException
      ) and
      c.getVariable().getAnAccess() = gm.getQualifier() and
      gm.getMethod().getName().regexpMatch("get(Localized)?Message|toString") and
      n1.asExpr() = call.getAnArgument() and
      n2.asExpr() = gm
    )
  }
}

/**
 * Convey taint from globally tainted objects to their fields
 */
private class GetterTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      m.getName().matches("get%") and
      m.getNumberOfParameters() = 0 and
      n1.asExpr() = ma.getQualifier() and
      n2.asExpr() = ma
    )
  }
}
/*
 * private class SetterTaintStep extends TaintTracking::AdditionalTaintStep {
 *  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
 *    exists(MethodAccess ma, Method m |
 *      ma.getMethod() = m and
 *      m.getName().matches("set%") and
 *      m.getNumberOfParameters() = 1 and
 *      ma.getEnclosingCallable().getDeclaringType().getName().matches("%Factory") and
 *      n1.asExpr() = ma.getArgument(0) and
 *      n2.asExpr() = ma.getQualifier()
 *    )
 *  }
 * }
 *
 * class GlobalSanitizer extends TaintTracking::Sanitizer {
 *  override predicate sanitize(DataFlow::Node node) {
 *    node.asExpr().(MethodAccess).getMethod().hasName("getInputStream") or
 *    node.asExpr().(MethodAccess).getMethod().hasName("getHostName")
 *  }
 * }
 */

