
private import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.security.HardcodedCredentials


abstract class Hardcoded extends DataFlow::Node { }

class HCExpr extends Hardcoded {
    HCExpr() {
        this.asExpr() instanceof HardcodedExpr and
        not this.asExpr().getEnclosingCallable() instanceof ToStringMethod
    }
}

