/**
 * @name Attack Surface
 * @description Application attack surface
 * @kind table
 * @id githubsecuritylab/attack-surface
 * @tags audit
 */

import cpp
import semmle.code.cpp.models.interfaces.FlowSource

from RemoteFlowSourceFunction source
where not source.getLocation().getFile().getRelativePath().matches("%/test/%")
select source, "remote", source.getLocation().getFile().getRelativePath(),
  source.getLocation().getStartLine(), source.getLocation().getEndLine(),
  source.getLocation().getStartColumn(), source.getLocation().getEndColumn()
