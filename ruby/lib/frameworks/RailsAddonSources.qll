/**
 * Additional sources that are not yet covered by CodeQL's rails sources (and not included by the Rack sources).
 * https://api.rubyonrails.org/classes/ActionDispatch/Request.html
 */

private import codeql.ruby.AST
private import codeql.ruby.ApiGraphs
private import codeql.ruby.Concepts
private import codeql.ruby.DataFlow
private import codeql.ruby.frameworks.ActionController

module RailsAddonSources {
  
  /**
   * A call to `request` in a Rails ActionController controller class.
   * The class ActionControllerRequest was copied from the experimental WeakParams query.
   */
  class ActionControllerRequest extends DataFlow::Node {
    ActionControllerRequest() {
      exists(DataFlow::CallNode c |
        c.asExpr().getExpr().getEnclosingModule() instanceof ActionControllerControllerClass and
        c.getMethodName() = "request"
      |
        c.flowsTo(this)
      )
    }
  }

  //TODO: this needs expansion (e.g., include request.body separately for Rails)
  class RawPostMethodCall extends DataFlow::CallNode {
    RawPostMethodCall() {
      this.getReceiver() instanceof ActionControllerRequest and
      this.getMethodName() = "raw_post"
    }
  }

  class RawPostMethodCallSource extends Http::Server::RequestInputAccess::Range {
    RawPostMethodCallSource() {
      exists(DataFlow::CallNode rawPost |
        rawPost instanceof RawPostMethodCall and
        this = rawPost
      )
    }

    override string getSourceType() { result = "request.raw_post (Rails)" }
    override Http::Server::RequestInputKind getKind() { result = "body" }
  }
}
