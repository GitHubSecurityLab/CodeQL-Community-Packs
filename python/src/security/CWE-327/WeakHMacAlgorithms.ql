/**
 * @name Use of Cryptographically Weak HMAC Algorithm
 * @description Use of Cryptographically Weak HMAC Algorithm
 * @kind problem
 * @id githubsecuritylab/weak-cryptographic-hmac-algorithm
 * @problem.severity warning
 * @security-severity 5.0
 * @sub-severity medium
 * @precision medium
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-330
 */

import python
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.concepts.internal.CryptoAlgorithmNames

from DataFlow::Node digest, DataFlow::CallCfgNode calls
where
  // https://docs.python.org/3/library/hmac.html#hmac.new
  // https://docs.python.org/3/library/hmac.html#hmac.digest
  // hmac.new(app.secret_key.encode(), data.encode(), digestmod=hashlib.md5).hexdigest()
  calls = API::moduleImport("hmac").getMember(["new", "digest"]).getACall() and
  (
    // new(2) and digest(2)
    digest = calls.getArgByName("digestmod") or
    digest = calls.getArgByName("digest") or
    digest = calls.getArg(2)
  ) and
  digest.asExpr() =
    API::moduleImport("hashlib").getMember(["md5", "sha1"]).getAValueReachableFromSource().asExpr()
select calls.asExpr(), "Weak HMAC Algorithm"
