/**
 * @name Deserializing XML from user-controlled data
 * @description Parsing user-controlled XML data (e.g. allowing expansion of external entity
 * references) may lead to disclosure of confidential data or denial of service.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.0
 * @precision high
 * @id githubsecuritylab/xxe-local-string-taint
 * @tags security
 *       local
 *       external/cwe/cwe-611
 *       external/cwe/cwe-776
 *       external/cwe/cwe-827
 *       external/cwe/cwe-502
 */

private import semmle.python.dataflow.new.DataFlow
private import ghsl.XMLLocalLib
import XmlStringTaint::PathGraph

from XmlStringTaint::PathNode source, XmlStringTaint::PathNode sink
where XmlStringTaint::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe parsing of XML from local $@.", source.getNode(),
  "user input"
