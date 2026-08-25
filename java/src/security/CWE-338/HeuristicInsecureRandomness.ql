/**
 * @name Heuristic insecure randomness
 * @description Using a cryptographically weak pseudo-random number generator, such as
 *              `java.util.Random`, to produce a value whose surrounding names suggest it is
 *              security-sensitive may allow an attacker to predict that value.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 3.7
 * @precision low
 * @id githubsecuritylab/java/heuristic-insecure-randomness
 * @tags security
 *       external/cwe/cwe-338
 */

import java
import semmle.code.java.security.RandomQuery
import semmle.code.java.security.InsecureRandomnessQuery

/**
 * Gets a "suspicious" name pattern that suggests a value is security-sensitive.
 *
 * This extends the `suspicious()` terms from
 * `semmle.code.java.security.SensitiveActions` with additional terms that are commonly
 * used to name values which must be unpredictable, such as tokens, secrets, keys,
 * nonces, salts, and authorization or verification codes.
 */
private string sus() {
  result =
    [
      // Terms taken from the `suspicious()` predicate in `SensitiveActions.qll`.
      "%password%", "%passwd%", "pwd", "%account%", "%accnt%", "%trusted%", "%refresh%token%",
      "%secret%token",
      // Additional terms for values that are expected to be unpredictable.
      "%token%", "%secret%", "%nonce%", "%salt%", "%otp%", "%passcode%", "%passphrase%",
      "%credential%", "%apikey%", "%api_key%", "%sessionid%", "%session_id%", "%csrf%", "%xsrf%",
      "%secretkey%", "%privatekey%", "%signingkey%", "%encryptionkey%", "%authoriz%", "%authcode%",
      "%verification%code%", "%verificationcode%", "%confirmation%code%", "%confirmationcode%",
      "%security%code%", "%securitycode%", "%activation%code%", "%activationcode%", "%pincode%"
    ]
}

/**
 * Gets a lowercased identifier name related to the random value produced at `source`
 * that may indicate the value is used for a security-sensitive purpose.
 */
private string getASensitiveContextName(RandomDataSource source) {
  // The name of the method or constructor that produces the random value.
  result = source.getEnclosingCallable().getName().toLowerCase()
  or
  // The name of a variable that the random value is directly assigned to.
  exists(Variable v | v.getAnAssignedValue() = source.getOutput() |
    result = v.getName().toLowerCase()
  )
  or
  // The name of the variable holding the `Random` instance that produced the value.
  exists(Variable v | source.getQualifier() = v.getAnAccess() | result = v.getName().toLowerCase())
}

from RandomDataSource source, string name
where
  // Restrict to insecure sources of randomness (e.g. `java.util.Random`, `Math.random`),
  // excluding safe implementations such as `java.security.SecureRandom`.
  source.getOutput() = any(InsecureRandomnessSource s).asExpr() and
  // Report each source once, using the alphabetically-first matching name.
  name = min(string n | n = getASensitiveContextName(source) and n.matches(sus()) | n)
select source,
  "Insecure randomness: this value is produced by a cryptographically weak random number generator, but '"
    + name +
    "' suggests it is used in a security-sensitive context. Use java.security.SecureRandom instead."
