/**
 * @name List of all known sources (remote, local, etc.)
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id java/debugging/sources
 * @tags debugging
 */

import java
import ghsl

from AllSources sources, string threatModel
where threatModel = sources.getThreatModel()
// Local sources
// sources.getThreatModel() = "local"
select sources, "source[" + threatModel + "]"
