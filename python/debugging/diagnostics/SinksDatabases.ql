/**
 * @name Database Sinks Diagnostic
 * @id ghsl/diagnostics/database-sinks
 * @description List all database sinks
 * @kind diagnostic
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.SqlInjectionCustomizations

from SqlInjection::Sink s, Expr n
where
  s.getScope().inSource() and
  n = s.asExpr()
select n, ""
