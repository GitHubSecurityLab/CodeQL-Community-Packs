/**
 * @name Use of Cryptographically Weak Pseudo-Random Number Generator
 * @description Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG).
 * @kind problem
 * @id githubsecuritylab/weak-cryptographic-prng
 * @problem.severity warning
 * @security-severity 6.0
 * @sub-severity medium
 * @precision low
 * @tags security
 *       external/cwe/cwe-338
 */

import python
import semmle.python.ApiGraphs

abstract class RandomNumberGeneratorSinks extends DataFlow::Node { }

class OSRandom extends RandomNumberGeneratorSinks {
  OSRandom() {
    exists(DataFlow::Node call |
      // https://docs.python.org/3/library/os.html#os.getrandom
      call = API::moduleImport("os").getMember("getrandom").getACall() and
      this = call
    )
  }
}

class PyRandom extends RandomNumberGeneratorSinks {
  PyRandom() {
    exists(DataFlow::Node call |
      (
        // https://docs.python.org/3/library/random.html#random.random
        call = API::moduleImport("random").getMember("random").getACall()
        or
        // https://docs.python.org/3/library/random.html#random.randbytes
        call = API::moduleImport("random").getMember("randbytes").getACall()
      ) and
      this = call
    )
  }
}

from RandomNumberGeneratorSinks rngs
select rngs.asExpr(), "Using weak PRNG"
