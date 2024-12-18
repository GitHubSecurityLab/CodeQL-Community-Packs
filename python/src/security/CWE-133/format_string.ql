/**
 * @name Python user-controlled format string
 * @description User-controlled format string can result in Denial-of-Service or information leaks
 * @kind path-problem
 * @problem.severity error
 * @id githubsecuritylab/format-string
 * @precision low
 * @tags format-string
 *       python
 *       security
 *       external/cwe/cwe-134
 *       external/cwe/cwe-133
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import format_string
import FormatStringTaint::PathGraph

from FormatStringTaint::PathNode userdata, FormatStringTaint::PathNode format_string
where FormatStringTaint::flowPath(userdata, format_string)
select format_string.getNode(), userdata, format_string, "$@ used as format string: $@.",
  userdata.getNode(), "Untrusted data", format_string, format_string.getNode().asExpr().toString()
