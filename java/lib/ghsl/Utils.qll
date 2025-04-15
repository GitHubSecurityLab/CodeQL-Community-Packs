/**
 * A collection of utility predicates and classes for the Java library.
 */

private import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.ExternalFlow
private import semmle.code.java.dataflow.FlowSources
// Sinks
private import semmle.code.java.security.QueryInjection
private import semmle.code.java.security.CommandLineQuery
private import semmle.code.java.security.LdapInjection
private import semmle.code.java.security.LogInjection
private import semmle.code.java.security.OgnlInjection
private import semmle.code.java.security.RequestForgery
private import semmle.code.java.security.TemplateInjection

/**
 * Filter nodes by its location (relative path or base name).
 */
bindingset[relative_path]
predicate findByLocation(DataFlow::Node node, string relative_path, int linenumber) {
  node.getLocation().getFile().getRelativePath().matches(relative_path) and
  node.getLocation().getStartLine() = linenumber
}

/**
 * This will only show sinks that are callable (method calls)
 */
predicate isCallable(DataFlow::Node sink) { sink.asExpr() instanceof MethodCall }

/**
 * Check if the source node is a method parameter.
 */
predicate checkSource(DataFlow::Node source) {
  exists(source.asParameter())
  or
  source.asExpr() instanceof MethodCall
}

/**
 * Local sources
 */
class LocalSources = LocalUserInput;

/**
 * List of all the souces
 */
class AllSources extends DataFlow::Node {
    private string threadmodel;

  AllSources() {
    this instanceof LocalUserInput and
    threadmodel = "local"
    or
    this instanceof RemoteFlowSource and
    threadmodel = "remote"
    or
    this instanceof ActiveThreatModelSource
    and
    threadmodel = this.(SourceNode).getThreatModel()
  }

  /**
   * Gets the source threat model.
   */
  string getThreatModel() {
    result = threadmodel
  }
}

/**
 * List of all the sinks that we want to check.
 */
class AllSinks extends DataFlow::Node {
  private string sink;

  AllSinks() {
    this instanceof QueryInjectionSink
    and 
    sink = "QueryInjectionSink"
    or
    this instanceof CommandInjectionSink
    and
    sink = "CommandInjectionSink"
    or
    this instanceof LdapInjectionSink
    and
    sink = "LdapInjectionSink"
    or
    this instanceof LogInjectionSink
    and
    sink = "LogInjectionSink"
    or
    this instanceof OgnlInjectionSink
    and
    sink = "OgnlInjectionSink"
    or
    this instanceof RequestForgerySink
    and
    sink = "RequestForgerySink"
    or
    this instanceof TemplateInjectionSink
    and
    sink = "TemplateInjectionSink"
    or
    // All MaD sinks
    sinkNode(this, _)
    and
    sink = "MaD"
  }
  
  /**
   * Gets the sink sink type.
   */
  string sinkType() {
    result = sink
  }
}
