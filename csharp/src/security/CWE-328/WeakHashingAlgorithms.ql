/**
 * @name Use of Cryptographically Weak Hash Algorithms
 * @description Use of Cryptographically Weak Hash Algorithms
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @sub-severity medium
 * @precision medium
 * @id githubsecuritylab/weak-cryptographic-hash-algorithms
 * @tags security
 *       audit
 *       external/cwe/cwe-328
 */

import csharp

predicate incorrectUseOfMD5CryptoServiceProvider(ObjectCreation e, string msg) {
  e.getType().(Class).hasQualifiedName("System.Security.Cryptography", "MD5CryptoServiceProvider") and
  msg =
    "This function creates a new MD5CryptoServiceProvider() object, which uses a cryptographically weak hash algorithm"
}

predicate incorrectUseOfMD5Create(Call e, string msg) {
  (
    e.getType().(Class).hasQualifiedName("System.Security.Cryptography", "MD5") and
    e.getTarget().hasName("Create")
    or
    e.getType().(Class).hasQualifiedName("System.Security.Cryptography", "HashAlgorithm") and
    e.getTarget().hasName("Create") and
    (
      e.getArgument(0).(StringLiteral).getValue() = "MD5" or
      e.getArgument(0).(StringLiteral).getValue() = "System.Security.Cryptography.MD5"
    )
  ) and
  msg =
    "This function calls the MD5.Create() or HashAlgorithm.Create() method, which uses a cryptographically weak hash algorithm"
}

from Expr e, string msg
where
  incorrectUseOfMD5CryptoServiceProvider(e, msg) or
  incorrectUseOfMD5Create(e, msg)
select e, msg
