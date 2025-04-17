/**
 * @name List of all known sinks
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision high
 * @id py/debugging/sinks
 * @tags debugging
 */

import python
import ghsl

from AllSinks sinks
select sinks, "sink[" + sinks.sinkType() + "]"
