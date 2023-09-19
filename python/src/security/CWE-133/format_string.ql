/**
 * @name Python user-controlled format string
 * @description User-controlled format string can result in Denial-of-Service or information leaks
 * @kind path-problem
 * @problem.severity error
 * @id python/format-string
 * @precision low
 * @tags format-string
 *       python
 *       security
 *       external/cwe/cwe-134
 *       external/cwe/cwe-133
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import DataFlow::PathGraph

private import format_string

from DataFlow::PathNode userdata, DataFlow::PathNode format_string, FormatStringTaintConfiguration format_string_config
where format_string_config.hasFlowPath(userdata, format_string)
select format_string.getNode(), userdata, format_string, "$@ used as format string: $@.", userdata.getNode(), "Untrusted data", format_string, format_string.getNode().asExpr().toString()
