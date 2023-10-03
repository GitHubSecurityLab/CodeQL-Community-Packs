/**
 * @name Resolving XML external entity in user-controlled data
 * @description Parsing user-controlled XML documents and allowing expansion of external entity
 * references may lead to disclosure of confidential data or denial of service.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.0
 * @precision high
 * @id githubsecuritylab/xxe-local
 * @tags security
 *       external/cwe/cwe-611
 *       external/cwe/cwe-776
 *       external/cwe/cwe-827
 */

import java
import semmle.code.java.security.XmlParsers
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
//import DataFlow::PathGraph
import ghsl.LocalSources

module SafeSAXSourceFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src.asExpr() instanceof SafeSaxSource }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(XmlParserCall parse).getSink() }

  int fieldFlowBranchLimit() { result = 0 }
}

module SafeSAXSourceFlow = TaintTracking::Global<SafeSAXSourceFlowConfig>;

class UnsafeXxeSink extends DataFlow::ExprNode {
  UnsafeXxeSink() {
    not SafeSAXSourceFlow::flowTo(this) and
    exists(XmlParserCall parse |
      parse.getSink() = this.getExpr() and
      not parse.isSafe()
    )
  }
}

module XXELocalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof LocalUserInput and
    not exists(DataFlow::Node src | src.asExpr() instanceof SafeSaxSource)
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeXxeSink }
}

module XXELocalFlow = TaintTracking::Global<XXELocalConfig>;

import XXELocalFlow::PathGraph

from XXELocalFlow::PathNode source, XXELocalFlow::PathNode sink
where XXELocalFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe parsing of XML file from $@.", source.getNode(),
  "user input"
