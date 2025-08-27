/**
 * @name Remote Sources Diagnostic
 * @id ghsl/diagnostics/remote-sources
 * @description List all remote sources
 * @kind diagnostic
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources

from RemoteFlowSource s, Expr n
where
  s.getScope().inSource() and
  n = s.asExpr()
select n, ""
