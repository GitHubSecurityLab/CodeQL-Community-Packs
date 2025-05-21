/**
 * @name Reflected cross-site scripting
 * @description Writing user input directly to an HTTP response allows for
 *              a cross-site scripting vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id githubsecuritylab/reflected-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
private import semmle.javascript.security.dataflow.XssThroughDomCustomizations
private import semmle.javascript.security.dataflow.DomBasedXssCustomizations
private import semmle.javascript.security.dataflow.Xss::Shared as Shared
import XssFlow::PathGraph

/**
 * A taint-tracking configuration for reasoning about XSS.
 */
module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof XssThroughDom::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof DomBasedXss::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof DomBasedXss::Sanitizer }
}

module XssFlow = TaintTracking::Global<XssConfig>;

// Additional Source
class ReactUseQueryParams extends XssThroughDom::Source {
  ReactUseQueryParams() {
    this = DataFlow::moduleMember("use-query-params", "useQueryParams").getACall()
    // TODO: Might want to get the `query` prop
  }
}

from XssFlow::PathNode source, XssFlow::PathNode sink
where XssFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to $@.",
  source.getNode(), "user-provided value"
