/**
 * @name Attack Surface
 * @description Application attack surface
 * @kind table
 * @id githubsecuritylab/attack-surface
 * @tags audit
 */

import javascript

from RemoteFlowSource source
where not source.getFile().getRelativePath().matches("%/test/%")
select source, source.getSourceType(), source.getFile().getRelativePath(), source.getStartLine(),
  source.getEndLine(), source.getStartColumn(), source.getEndColumn()
