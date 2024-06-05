private import go

module LocalSources {
  private import semmle.go.dataflow.DataFlow
  private import semmle.go.dataflow.TaintTracking
  private import semmle.go.dataflow.ExternalFlow as ExternalFlow
  private import semmle.go.Scopes

  /**
   * A source of data that is controlled by the local user.
   */
  abstract class Range extends DataFlow::Node { }

  /**
   * Support for Local Sources
   */
  class MaDLocalSource extends Range {
    MaDLocalSource() { ExternalFlow::sourceNode(this, "local") }
  }

  class OsCmd extends LocalSources::Range {
    OsCmd() {
      exists(ValueEntity read, DataFlow::Package pkg |
        read.getScope().getEntity(_) = pkg.getScope().getEntity(_) and
        this.toString() = "selection of Run"
      )
    }
  }

  class OsExec extends LocalSources::Range {
    OsExec() {
      exists(ValueEntity read, DataFlow::Package pkg |
        read.getScope().getEntity(_) = pkg.getScope().getEntity(_) and
        this.toString() = "selection of Command"
      )
    }
  }
}
