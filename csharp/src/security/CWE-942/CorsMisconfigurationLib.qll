import csharp
import DataFlow
import ghsl.ConstExpressions

/**
 * Gets the actual callable corresponding to the expression `e`.
 */
Callable getCallableFromExpr(Expr e) {
  exists(Expr dcArg | dcArg = e.(DelegateCreation).getArgument() |
    result = dcArg.(CallableAccess).getTarget() or
    result = dcArg.(AnonymousFunctionExpr)
  )
  or
  result = e
}

/**
 * Holds if SetIsOriginAllowed always returns true. This sets the Access-Control-Allow-Origin to the requester
 */
predicate setIsOriginAllowedReturnsTrue(MethodCall mc) {
  mc.getTarget()
      .hasFullyQualifiedName("Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder",
        "SetIsOriginAllowed") and
  alwaysReturnsTrue(mc.getArgument(0))
}

/**
 * Holds if UseCors is called with the relevant cors policy
 */
predicate usedPolicy(MethodCall add_policy) {
  exists(MethodCall uc |
    uc.getTarget()
        .hasFullyQualifiedName("Microsoft.AspNetCore.Builder.CorsMiddlewareExtensions", "UseCors") and
    (
      // Same hardcoded name
      uc.getArgument(1).getValue() = add_policy.getArgument(0).getValue() or
      // Same variable access
      uc.getArgument(1).(VariableAccess).getTarget() =
        add_policy.getArgument(0).(VariableAccess).getTarget() or
      DataFlow::localExprFlow(add_policy.getArgument(0), uc.getArgument(1))
    )
  ) and
  add_policy
      .getTarget()
      .hasFullyQualifiedName("Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions", "AddPolicy")
}
