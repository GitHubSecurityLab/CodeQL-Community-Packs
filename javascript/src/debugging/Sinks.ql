/**
 * @name List of all known sinks
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision high
 * @id js/debugging/sinks
 * @tags debugging
 */

import javascript
import ghsl

from AllSinks sinks
// where
/// Filter by file and line number
// filterByLocation(sinks, "app.js", _)
select sinks, "sink[" + sinks.sinkType() + "]"
