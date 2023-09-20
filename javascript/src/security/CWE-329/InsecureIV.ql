/**
 * @name Insecure or static IV used in cryptographic function with Node crypto module
 * @description Initialization Vectors (IV) must be generated securely and not reused, for most cryptographic algorithms (Node Crypto)
 * @kind path-problem
 * @problem.severity error
 * @security-severity 4.3
 * @precision high
 * @id githubsecuritylab/crypt/insecure-iv
 * @tags crypt
 *       security
 *       experimental
 *       external/cwe/cwe-329
 *       external/cwe/cwe-1204
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph
import github.InsecureIV

from InsecureIVConfiguration insecurecfg, DataFlow::PathNode source, DataFlow::PathNode sink
where
  insecurecfg.hasFlowPath(source, sink) and
  not exists(DataFlow::Node randomSource, RandomTaintsSourceConfiguration randomConfig |
    randomSource instanceof SecureRandomSource
  |
    randomConfig.hasFlow(randomSource, source.getNode())
  ) and
  not knownCryptTest(sink.getNode())
select sink, source, sink,
  "Insecure Initialization Vector (IV) used for cryptographic function. With a few exceptions, it is best to use a secure random source for IVs."
