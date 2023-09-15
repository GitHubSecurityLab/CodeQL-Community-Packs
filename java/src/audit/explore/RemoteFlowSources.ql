/**
 * @name Attack Surface
 * @description Application attack surface
 * @kind table
 * @id githubsecuritylab/attack-surface
 * @tags audit
 */

import java
import semmle.code.java.dataflow.FlowSources

from RemoteFlowSource source, Location l
where
  not source.getLocation().getFile().getRelativePath().matches("%/src/test/%") and
  l = source.getLocation()
select source, source.getSourceType()
