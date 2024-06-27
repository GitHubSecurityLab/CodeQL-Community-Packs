/**
 * @name Local Sources Diagnostic
 * @id ghsl/diagnostics/local-sources
 * @description List all local sources
 * @kind diagnostic
 */

import python
import semmle.python.dataflow.new.DataFlow
// Helpers
import ghsl.LocalSources

from LocalSources::Range s, Expr n
where
  s.getScope().inSource() and
  n = s.asExpr()
select n, ""
