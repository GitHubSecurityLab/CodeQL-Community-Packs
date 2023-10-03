import go
import semmle.go.frameworks.stdlib.Fmt

class DynamicStrings extends DataFlow::Node {
    DynamicStrings() {
        // fmt format string
        exists(Fmt::Sprinter formatter |
            this = formatter.getACall()
        )
        or
        // binary expression
        exists(BinaryExpr expr |
            this.asExpr() = expr.getLeftOperand() and
            expr.getOperator() = "+"
        )
    }
}