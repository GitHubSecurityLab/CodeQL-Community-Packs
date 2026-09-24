/**
 * @name Sources
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id py/debugging/sources
 * @tags debugging
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
// Helpers
private import ghsl.Helpers
private import ghsl.LocalSources

class Sources extends DataFlow::Node {
  Sources() {
    this instanceof RemoteFlowSource
    or
    this instanceof LocalSources::Range
  }
}

from Sources sources
where sources.getScope().inSource()
select sources, "source"
