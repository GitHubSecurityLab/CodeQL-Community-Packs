/**
 * @name Deserializing XML from user-controlled filename
 * @description Parsing XML data from a user-controlled filename (e.g. allowing expansion of external entity
 * references) may lead to disclosure of confidential data or denial of service.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.0
 * @precision high
 * @id githubsecuritylab/xxe-local-file-taint
 * @tags security
 *       local
 *       external/cwe/cwe-611
 *       external/cwe/cwe-776
 *       external/cwe/cwe-827
 *       external/cwe/cwe-502
 */

private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import ghsl.XMLLocalLib
import XmlFileTaint::PathGraph

from XmlFileTaint::PathNode source, XmlFileTaint::PathNode sink
where XmlFileTaint::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe parsing of XML from locally-provided filename $@.",
  source.getNode(), "user input"
