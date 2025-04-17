private import go
private import semmle.go.dataflow.DataFlow
private import semmle.go.dataflow.TaintTracking
private import semmle.go.frameworks.stdlib.Fmt

/**
 * Find Node at Location
 */
predicate filterByLocation(DataFlow::Node node, string relative_path, int linenumber) {
  node.getLocation().getFile().getRelativePath() = relative_path and
  node.getLocation().getStartLine() = linenumber
}

/**
 * List of all the souces
 */
class AllSources extends DataFlow::Node {
  private string threatmodel;

  AllSources() {
    this instanceof RemoteFlowSource::Range and
    threatmodel = "remote"
    or
    this instanceof LocalSources and
    threatmodel = "local"
  }

  /**
   * Gets the source threat model.
   */
  string getThreatModel() { result = threatmodel }
}

/**
 * Local sources
 */
class LocalSources extends DataFlow::Node {
  LocalSources() {
    this.(SourceNode).getThreatModel() = "local"
  }
}

class DynamicStrings extends DataFlow::Node {
    DynamicStrings() {
        // fmt format string
        exists(Fmt::Sprinter formatter |
            this = formatter.getACall()
        )
        or
        // binary expression
        exists(BinaryExpr expr |
            this.asExpr() = expr.getLeftOperand() and
            expr.getOperator() = "+"
        )
    }
}