/**
 * @name Hard-coded credentials
 * @description Credentials are hard coded in the source code of the application.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cs/hardcoded-credentials-symmetricsecuritykey
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-321
 *       external/cwe/cwe-798
 */

import csharp

private import DataFlow::PathGraph

private import github.HardcodedCredentials


from DataFlow::PathNode source, DataFlow::PathNode sink, LiteralToSecurityKeyConfig config
where config.hasFlowPath(source, sink)
select source, sink, source, "Hard-coded credential $@ used as SymmetricSecurityKey $@",
  source.getNode().asExpr(), source.getNode().toString(), sink.getNode().asExpr(), "here"
