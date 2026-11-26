/**
 * @name Sensitive action guarded by reverse DNS lookup
 * @description Deciding whether to perform a sensitive action based on the host name returned
 *              by a reverse DNS lookup allows an attacker who controls the DNS (PTR) record of
 *              their IP address to bypass the check.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id githubsecuritylab/cs/reverse-dns-user-controlled-bypass
 * @tags security
 *       experimental
 *       external/cwe/cwe-350
 *       external/cwe/cwe-807
 *       external/cwe/cwe-247
 */

import csharp
import semmle.code.csharp.security.dataflow.ConditionalBypassQuery as ConditionalBypassQuery
import ReverseDnsConditionalBypassQuery
import ReverseDnsConditionalBypass::PathGraph

from ReverseDnsConditionalBypass::PathNode source, ReverseDnsConditionalBypass::PathNode sink
where ReverseDnsConditionalBypass::flowPath(source, sink)
select sink.getNode(), source, sink, "This condition guards a sensitive $@, but a $@ controls it.",
  sink.getNode().(ConditionalBypassQuery::Sink).getSensitiveMethodCall(), "action",
  source.getNode(), "reverse DNS host name"
