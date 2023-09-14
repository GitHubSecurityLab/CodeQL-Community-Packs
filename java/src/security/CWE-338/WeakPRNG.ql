/**
 * @name Use of Cryptographically Weak Pseudo-Random Number Generator
 * @description Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG).
 * @kind problem
 * @id java/weak-cryptographic-algorithm
 * @problem.severity warning
 * @security-severity 6.0
 * @sub-severity medium
 * @precision low
 * @tags security
 *       external/cwe/cwe-330
 *       external/cwe/cwe-338
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2

abstract class RandomNumberGeneratorSinks extends DataFlow::Node { }

class MathRandom extends RandomNumberGeneratorSinks {
  MathRandom() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Math") and
      ma.getMethod().getName() = "random" and
      this.asExpr() = ma
    )
  }
}

class RandomUtils extends RandomNumberGeneratorSinks {
  RandomUtils() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Random") and
      (
        ma.getMethod().getName() = "next" or
        ma.getMethod().getName() = "nextBytes" or
        ma.getMethod().getName() = "nextDouble" or
        ma.getMethod().getName() = "nextFloat" or
        ma.getMethod().getName() = "nextInt" or
        ma.getMethod().getName() = "nextLong"
      ) and
      this.asExpr() = ma
    )
  }
}

from RandomNumberGeneratorSinks rngs
select rngs.asExpr(), "Using weak PRNG"
