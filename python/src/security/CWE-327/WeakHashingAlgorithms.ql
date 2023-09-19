/**
 * @name Use of a broken or weak cryptographic algorithm
 * @description Using broken or weak cryptographic algorithms can compromise security.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @sub-severity medium
 * @precision high
 * @id githubsecuritylab/weak-cryptographic-algorithm
 * @tags security
 *       experimental
 *       external/cwe/cwe-327
 */

import python
import semmle.python.Concepts

from Cryptography::CryptographicOperation operation, Cryptography::HashingAlgorithm algorithm
where
  algorithm = operation.getAlgorithm() and
  algorithm.isWeak()
select operation,
  "Using '" + algorithm.getName() + "' hashing algorithm can be dangerous and should not be used"
