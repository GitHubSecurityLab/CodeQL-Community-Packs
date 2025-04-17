private import python
private import semmle.python.ApiGraphs
private import semmle.python.Concepts
private import semmle.python.dataflow.new.DataFlow
private import ghsl.LocalSources
private import ghsl.Sinks

/**
 * Find Node at Location
 */
predicate filterByLocation(DataFlow::Node node, string relative_path, int linenumber) {
  node.getLocation().getFile().getRelativePath() = relative_path and
  node.getLocation().getStartLine() = linenumber
}

/**
 * Check if the source node is a method parameter
 */
predicate functionParameters(DataFlow::Node node) {
  (
    // // Function Call Parameters
    node instanceof DataFlow::ParameterNode
    or
    // Function Call Arguments
    node instanceof DataFlow::ArgumentNode
  ) and
  node instanceof AllSinks and
  node.getScope().inSource()
}


/**
 * List of all the souces
 */
class AllSources extends DataFlow::Node {
  private string threatmodel;

  AllSources() {
    exists(ThreatModelSource tms |
      threatmodel = tms.getThreatModel() and
      this = tms
    )
    or
    this instanceof LocalSources::Range and
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
class LocalSources = LocalSources::Range;


// List of all the format strings
// - python/ql/lib/semmle/python/dataflow/new/internal/TaintTrackingPrivate.qll
class DynamicStrings extends DataFlow::Node {
  DynamicStrings() {
    (
      // s = f"WHERE name = '{input}'"
      exists(Fstring fmtstr | this.asExpr() = fmtstr)
      or
      // "SELECT * FROM users WHERE username = '{}'".format(username)
      exists(CallNode format, string methods, ControlFlowNode object |
        object = format.getFunction().(AttrNode).getObject(methods)
      |
        methods = "format" and
        this.asExpr() = format.getNode()
      )
      or
      exists(BinaryExpr expr |
        (
          // q = "WHERE name = %s" % username
          expr.getOp() instanceof Mod
          or
          // q = "WHERE name = " + username
          expr.getOp() instanceof Add
        ) and
        expr.getLeft().getParent() = this.asExpr()
      )
    ) and
    this.getScope().inSource()
  }
}
