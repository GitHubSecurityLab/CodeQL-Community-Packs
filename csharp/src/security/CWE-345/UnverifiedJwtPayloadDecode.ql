/**
 * @name JWT payload decoded without signature verification
 * @description Base64-decoding the payload segment of a JSON Web Token without verifying
 *              the token signature lets an attacker forge claims such as roles or user
 *              identifiers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id githubsecuritylab/cs/unverified-jwt-payload-decode
 * @tags security
 *       experimental
 *       external/cwe/cwe-345
 *       external/cwe/cwe-347
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import UnverifiedJwtPayloadDecodeFlow::PathGraph

/** A call to `string.Split` whose separator is the JWT segment separator `.`. */
class JwtSplitCall extends MethodCall {
  JwtSplitCall() {
    this.getTarget().hasFullyQualifiedName("System", "String", "Split") and
    exists(Expr sep | sep = this.getArgument(0) |
      sep.(CharLiteral).getValue() = "."
      or
      sep.(StringLiteral).getValue() = "."
    )
  }

  /** Holds if `aa` reads segment `index` of the result of this call. */
  predicate readsSegment(ArrayAccess aa, int index) {
    DataFlow::localExprFlow(this, aa.getQualifier()) and
    aa.getIndex(0).getValue().toInt() = index
  }

  /**
   * Gets an expression that holds the signature segment, or its decoded value. Local taint
   * steps follow conversions such as `byte[]` to `ReadOnlySpan<byte>`.
   */
  private Expr getASignatureValue() {
    exists(ArrayAccess signature | this.readsSegment(signature, 2) |
      TaintTracking::localExprTaint(signature, result)
      or
      exists(Base64DecodeCall decoder |
        DataFlow::localExprFlow(signature, decoder.getArgument(0)) and
        TaintTracking::localExprTaint(decoder, result)
      )
    )
  }

  /**
   * Holds if the signature segment flows into a comparison, or into an argument of a
   * method whose name contains `verify` or `equals`.
   */
  predicate verifiesSignature() {
    exists(ComparisonOperation comparison | this.getASignatureValue() = comparison.getAnOperand())
    or
    exists(MethodCall verification |
      this.getASignatureValue() = verification.getAnArgument() and
      verification.getTarget().getName().toLowerCase().matches(["%verify%", "%equals%"])
    )
  }
}

/**
 * An access to the payload segment (index 1) of a JWT split on `.`, where the
 * signature segment (index 2) is not used in a verification-like operation.
 */
class JwtPayloadSegment extends ArrayAccess {
  JwtSplitCall split;

  JwtPayloadSegment() {
    split.readsSegment(this, 1) and
    not split.verifiesSignature()
  }

  /** Gets the `Split` call whose result this access reads. */
  JwtSplitCall getSplitCall() { result = split }
}

/** A call to a base64 decoding method. */
class Base64DecodeCall extends MethodCall {
  Base64DecodeCall() {
    this.getTarget()
        .hasFullyQualifiedName("System", "Convert", ["FromBase64String", "TryFromBase64String"])
    or
    this.getTarget()
        .hasFullyQualifiedName("Microsoft.IdentityModel.Tokens", "Base64UrlEncoder",
          ["Decode", "DecodeBytes"])
    or
    this.getTarget()
        .hasFullyQualifiedName("Microsoft.AspNetCore.WebUtilities", "WebEncoders", "Base64UrlDecode")
  }
}

/**
 * Holds if `parameters` comes from a `TokenValidationParameters` object creation whose
 * initializer enables `ValidateIssuerSigningKey` and sets `IssuerSigningKey`.
 */
predicate hasSignatureValidationEnabled(Expr parameters) {
  exists(
    ObjectCreation creation, ObjectInitializer initializer, MemberInitializer enabled,
    MemberInitializer key
  |
    DataFlow::localExprFlow(creation, parameters) and
    initializer = creation.getInitializer() and
    enabled = initializer.getAMemberInitializer() and
    enabled.getLeftOperand().(PropertyAccess).getTarget().hasName("ValidateIssuerSigningKey") and
    enabled.getRightOperand().(BoolLiteral).getBoolValue() = true and
    key = initializer.getAMemberInitializer() and
    key.getLeftOperand().(PropertyAccess).getTarget().hasName("IssuerSigningKey")
  )
}

/**
 * Holds if the token whose payload is `payload` is validated by a JWT library, with
 * signing key validation enabled, before `decoder` runs.
 */
predicate validatedBeforeDecode(JwtPayloadSegment payload, Base64DecodeCall decoder) {
  exists(JwtSplitCall split, MethodCall validation |
    split = payload.getSplitCall() and
    validation
        .getTarget()
        .hasFullyQualifiedName("System.IdentityModel.Tokens.Jwt", "JwtSecurityTokenHandler",
          "ValidateToken") and
    DataFlow::localExprFlow(validation.getArgument(0), split.getQualifier()) and
    hasSignatureValidationEnabled(validation.getArgument(1)) and
    validation.getControlFlowNode().dominates(decoder.getControlFlowNode())
  )
  or
  exists(
    JwtSplitCall split, MethodCall validation, AwaitExpr awaited, IfStmt guard,
    LogicalNotExpr invalidResult, PropertyAccess isValid, ThrowStmt failure
  |
    split = payload.getSplitCall() and
    validation
        .getTarget()
        .hasFullyQualifiedName("Microsoft.IdentityModel.JsonWebTokens", "JsonWebTokenHandler",
          "ValidateTokenAsync") and
    DataFlow::localExprFlow(validation.getArgument(0), split.getQualifier()) and
    hasSignatureValidationEnabled(validation.getArgument(1)) and
    awaited.getExpr() = validation and
    DataFlow::localExprFlow(awaited, isValid.getQualifier()) and
    isValid.getTarget().hasName("IsValid") and
    invalidResult = guard.getCondition() and
    invalidResult.getOperand() = isValid and
    failure.getParent*() = guard.getThen() and
    guard.getControlFlowNode().dominates(decoder.getControlFlowNode())
  )
}

module UnverifiedJwtPayloadDecodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof JwtPayloadSegment }

  predicate isSink(DataFlow::Node sink) {
    exists(Base64DecodeCall decoder | sink.asExpr() = decoder.getArgument(0))
  }
}

module UnverifiedJwtPayloadDecodeFlow = TaintTracking::Global<UnverifiedJwtPayloadDecodeConfig>;

from UnverifiedJwtPayloadDecodeFlow::PathNode source, UnverifiedJwtPayloadDecodeFlow::PathNode sink
where
  UnverifiedJwtPayloadDecodeFlow::flowPath(source, sink) and
  not validatedBeforeDecode(source.getNode().asExpr(), sink.getNode().asExpr().getParent())
select sink.getNode(), source, sink,
  "$@ is base64-decoded without the token signature being verified, so its claims can be forged.",
  source.getNode(), "This JWT payload segment"
