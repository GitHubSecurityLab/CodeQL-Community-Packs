/**
 * @name Audit: Usage of Insecure XML Parser
 * @description Parsing XML using an insecure parser can lead to security issues.
 * @kind problem
 * @problem.severity error
 * @security-severity 6.0
 * @precision high
 * @id python/audit/xxe-local-file
 * @tags security
 *       external/cwe/cwe-611
 *       external/cwe/cwe-776
 *       external/cwe/cwe-827
 *       external/cwe/cwe-502
 *       audit
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import github.XMLLocalLib

from DataFlow::Node source, DataFlow::Node sink
where
  exists(XmlParseFileCall call |
    source = call.getSource() and
    sink = call
  )
select sink, "Unsafe parsing of XML from fixed file name $@.", source,
  source.asExpr().(StrConst).getLiteralValue().toString()
