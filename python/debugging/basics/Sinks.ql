/**
 * @name Sinks
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id py/debugging/sinks
 * @tags debugging
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
// Helpers
private import ghsl.Helpers

from DataFlow::Node sinks
where
  dangerousSinks(sinks) and
  sinks.getScope().inSource()
select sinks, "sink"
