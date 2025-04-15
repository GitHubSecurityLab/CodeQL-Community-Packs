/**
 * A collection of utility predicates and classes for JavaScript
 */
private import javascript
private import semmle.javascript.security.dataflow.CommandInjectionCustomizations
private import semmle.javascript.security.dataflow.CodeInjectionCustomizations
private import semmle.javascript.security.dataflow.LogInjectionQuery as LogInjection
private import semmle.javascript.security.dataflow.NosqlInjectionCustomizations
private import semmle.javascript.security.dataflow.Xss as Xss
private import semmle.javascript.security.dataflow.XxeCustomizations


/**
 * Filter results to a specific file and line number
 * 
 *  **Examples:**
 * 
 *  ```
 *  filterByLocation(sources, "db.js", 1)
 *  // or we don't care about the line numbers
 *  filterByLocation(sources, "db.js", _)
 *  ```
 */
predicate filterByLocation(DataFlow::Node node, string relative_path, int linenumber) {
  node.getLocation().getFile().getRelativePath() = relative_path and
  node.getLocation().getStartLine() = linenumber
}


/**
 * All Sources (Remote and Local)
 */
class AllSources extends DataFlow::Node  {
    private string threadmodel;

    AllSources() {
        this instanceof RemoteSources and
        threadmodel = "remote" or
        this instanceof LocalSources and
        threadmodel = "local"
    }

  /**
   * Gets the source threat model.
   */
  string getThreatModel() {
    result = threadmodel
  }
}

/**
 * Remote Sources (HTTP frameworks, etc)
 */
class RemoteSources extends ThreatModelSource {
  RemoteSources() { this.getThreatModel() = "remote" }
}

/**
 * Local Sources (CLI arguments, Filesystem, etc)
 */
class LocalSources extends ThreatModelSource {
  LocalSources() { this.getThreatModel() = "local" }
}

/**
 * List of all sinks
 */
class AllSinks extends DataFlow::Node {
  private string sink;

  AllSinks() {
    this instanceof CodeInjection::Sink and
    sink = "code-injection" or
    this instanceof CommandInjection::Sink and
    sink = "command-injection" or
    this instanceof LogInjection::Sink and
    sink = "log-injection" or
    this instanceof NosqlInjection::Sink and
    sink = "nosql-injection" or
    this instanceof Xss::Shared::Sink and
    sink = "xss" or
    this instanceof Xxe::Sink and
    sink = "xxe"
  }

  /**
   * Gets the sink threat model.
   */
  string sinkType() {
    result = sink
  }
}