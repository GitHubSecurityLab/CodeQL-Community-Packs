import csharp

/**
 * Holds if the `Callable` c throws any exception other than `ThrowsArgumentNullException`
 */
predicate callableMayThrowException(Callable c) {
  exists(ThrowStmt thre | c = thre.getEnclosingCallable()) and
  not callableOnlyThrowsArgumentNullException(c)
}

/**
 * Holds if any exception being thrown by the callable is of type `System.ArgumentNullException`
 * It will also hold if no exceptions are thrown by the callable
 */
predicate callableOnlyThrowsArgumentNullException(Callable c) {
  forall(ThrowElement thre | c = thre.getEnclosingCallable() |
    thre.getThrownExceptionType().hasFullyQualifiedName("System", "ArgumentNullException")
  )
}

/**
 * Hold if the `Expr` e is a `BoolLiteral` with value true,
 * the expression has a predictable value == `true`,
 * or if it is a `ConditionalExpr` where the `then` and `else` expressions meet `isExpressionAlwaysTrue` criteria
 */
predicate isExpressionAlwaysTrue(Expr e) {
  e.(BoolLiteral).getBoolValue() = true
  or
  e.getValue() = "true"
  or
  e instanceof ConditionalExpr and
  isExpressionAlwaysTrue(e.(ConditionalExpr).getThen()) and
  isExpressionAlwaysTrue(e.(ConditionalExpr).getElse())
  or
  exists(Callable callable |
    callableHasAReturnStmtAndAlwaysReturnsTrue(callable) and
    callable.getACall() = e
  )
}

/**
 * Holds if the lambda expression `le` always returns true
 */
predicate lambdaExprReturnsOnlyLiteralTrue(AnonymousFunctionExpr le) {
  isExpressionAlwaysTrue(le.getExpressionBody())
}

/**
 * Holds if the callable has a return statement and it always returns true for all such statements
 */
predicate callableHasAReturnStmtAndAlwaysReturnsTrue(Callable c) {
  c.getReturnType() instanceof BoolType and
  not callableMayThrowException(c) and
  forex(ReturnStmt rs | rs.getEnclosingCallable() = c |
    rs.getNumberOfChildren() = 1 and
    isExpressionAlwaysTrue(rs.getChildExpr(0))
  )
}

/**
 * Holds if `c` always returns `true`.
 */
predicate alwaysReturnsTrue(Callable c) {
  callableHasAReturnStmtAndAlwaysReturnsTrue(c)
  or
  lambdaExprReturnsOnlyLiteralTrue(c)
}
