/**
 * @name Attack Surface
 * @description Application attack surface
 * @kind table
 * @id githubsecuritylab/attack-surface
 * @tags audit
 */

import semmle.code.csharp.dataflow.flowsources.Remote

from RemoteFlowSource source
where not source.getLocation().getFile().getRelativePath().matches("%/test/%")
select source, source.getSourceType(), source.getLocation().getFile().getRelativePath(),
  source.getLocation().getStartLine(), source.getLocation().getEndLine(),
  source.getLocation().getStartColumn(), source.getLocation().getEndColumn()
