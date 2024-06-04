/**
 * @name Hard-coded credentials
 * @description Credentials are hard coded in the source code of the application.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id githubsecuritylab/hardcoded-credentials-symmetricsecuritykey
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-321
 *       external/cwe/cwe-798
 */

import csharp
private import ghsl.HardcodedCredentials
import LiteralToSecurityKeyFlow::PathGraph

from LiteralToSecurityKeyFlow::PathNode source, LiteralToSecurityKeyFlow::PathNode sink
where LiteralToSecurityKeyFlow::flowPath(source, sink)
select source, sink, source, "Hard-coded credential $@ used as SymmetricSecurityKey $@",
  source.getNode().asExpr(), source.getNode().toString(), sink.getNode().asExpr(), "here"
