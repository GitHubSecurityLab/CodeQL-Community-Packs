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
import DataFlow::PathGraph

/**
 * A taint-tracking configuration for reasoning about XSS.
 */
class XssConfiguration extends TaintTracking::Configuration {
  XssConfiguration() { this = "XssReact" }

  override predicate isSource(DataFlow::Node source) { source instanceof XssThroughDom::Source }

  override predicate isSink(DataFlow::Node sink) { sink instanceof DomBasedXss::Sink }

  override predicate isSanitizer(DataFlow::Node node) {
    super.isSanitizer(node) or
    node instanceof DomBasedXss::Sanitizer
  }
}

// Additional Source
class ReactUseQueryParams extends XssThroughDom::Source {
  ReactUseQueryParams() {
    this = DataFlow::moduleMember("use-query-params", "useQueryParams").getACall()
    // TODO: Might want to get the `query` prop
  }
}

from XssConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to $@.",
  source.getNode(), "user-provided value"
