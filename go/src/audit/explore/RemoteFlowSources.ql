/**
 * @name Attack Surface
 * @description Application attack surface
 * @kind table
 * @id githubsecuritylab/audit/attack-surface
 * @tags audit
 */

import semmle.go.security.FlowSources

from UntrustedFlowSource source
where not source.getFile().getRelativePath().matches("%/test/%")
select source, "remote", source.getFile().getRelativePath(), source.getStartLine(),
  source.getEndLine(), source.getStartColumn(), source.getEndColumn()
