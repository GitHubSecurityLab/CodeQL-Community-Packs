/**
 * @name List of all known sources (remote, local, etc.)
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision high
 * @id py/debugging/sources
 * @tags debugging
 */

import python
import ghsl

from AllSources sources, string threatModel
where threatModel = sources.getThreatModel()
// Local sources
// sources.getThreatModel() = "local"
select sources, "source[" + threatModel + "]"
