/**
 * @name List of all known sources (remote, local, etc.)
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision high
 * @id js/debugging/sources
 * @tags debugging
 */

import javascript
import ghsl

from AllSources sources, string threatModel
where
    sources.getThreatModel() = threatModel
select sources, "source[" + threatModel + "]"
