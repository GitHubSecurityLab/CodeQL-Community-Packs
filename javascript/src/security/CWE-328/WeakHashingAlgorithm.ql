/**
 * @name Using weak hashing algorithm
 * @description Using weak hashing algorithm
 * @kind problem
 * @problem.severity error
 * @security-severity 4.0
 * @precision medium
 * @id githubsecuritylab/weak-hashing
 * @tags security
 *       external/cwe/cwe-328
 */

import javascript

from CryptographicOperation crypto, HashingAlgorithm hashing
where crypto.getAlgorithm().isWeak() and crypto.getAlgorithm().getName() = hashing.getName()
select crypto, "weak hashing algorithms"
