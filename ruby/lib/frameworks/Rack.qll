/**
 * Additional sources to model the Rack request object.
 * (Rack provides a minimal, modular, and adaptable interface for developing web applications in Ruby.)
 * Ruby web frameworks such as Sinatra make use of the Rack interface.
 * Please note: Ruby on Rails exposes an a similar request interface like the rack request interface via ActionDispatch.
 * -> This means this Rack sources also expand the number of Rails sources as a by-product.
 * (https://api.rubyonrails.org/classes/ActionDispatch/Request.html)
 */

private import codeql.ruby.AST
private import codeql.ruby.Concepts

module Rack {
  /**
   * A call to the `request` method to retrieve Rack request object.
   */
  class RequestCall extends MethodCall {
    RequestCall() { this.getMethodName() = "request" }
  }

  /**
   * A call to the `request.body` method to retrieve the body of the Rack request object.
   */
  class RequestBodyCall extends MethodCall {
    RequestBodyCall() {
      exists(MethodCall request |
        request instanceof RequestCall and
        this.(MethodCall).getReceiver() = request and
        this.getMethodName() = "body"
      )
    }
  }

  /**
   * `request.body.read` source
   */
  class RequestBodyReadSource extends Http::Server::RequestInputAccess::Range {
    RequestBodyReadSource() {
      exists(MethodCall body, MethodCall read |
        body instanceof RequestBodyCall and
        read.(MethodCall).getReceiver() = body and
        read.getMethodName() = "read" and
        this.asExpr().getExpr() = read
      )
    }

    override string getSourceType() { result = "request.body.read" }

    override Http::Server::RequestInputKind getKind() { result = "body" }
  }

  /**
   * `request.body.string` source
   */
  class RequestBodyStringSource extends Http::Server::RequestInputAccess::Range {
    RequestBodyStringSource() {
      exists(MethodCall body, MethodCall stringcall |
        body instanceof RequestBodyCall and
        stringcall.(MethodCall).getReceiver() = body and
        stringcall.getMethodName() = "string" and
        this.asExpr().getExpr() = stringcall
      )
    }

    override string getSourceType() { result = "request.body.string" }

    override Http::Server::RequestInputKind getKind() { result = "body" }
  }

  /**
   * `request.query_string` source
   */
  class RequestQueryStringSource extends Http::Server::RequestInputAccess::Range {
    RequestQueryStringSource() {
      exists(MethodCall request, MethodCall queryString |
        request instanceof RequestCall and
        queryString.(MethodCall).getReceiver() = request and
        queryString.getMethodName() = "query_string" and
        this.asExpr().getExpr() = queryString
      )
    }

    override string getSourceType() { result = "request.query_string" }

    override Http::Server::RequestInputKind getKind() { result = "parameter" }
  }

  /**
   * A call to the `request.params` method to retrieve the combined GET/POST params of the Rack request object.
   */
  class RequestParamsCall extends MethodCall {
    RequestParamsCall() {
      exists(MethodCall request |
        request instanceof RequestCall and
        this.(MethodCall).getReceiver() = request and
        this.getMethodName() = "params"
      )
    }
  }

  /**
   * `request.params[foo]` source
   */
  class RequestParamsSource extends Http::Server::RequestInputAccess::Range {
    RequestParamsSource() {
      exists(MethodCall params, ElementReference elementRef |
        params instanceof RequestParamsCall and
        elementRef.(ElementReference).getReceiver() = params and
        this.asExpr().getExpr() = elementRef
      )
    }

    override string getSourceType() { result = "request.params[foo]" }

    override Http::Server::RequestInputKind getKind() { result = "parameter" }
  }

  /**
   * `request[foo]` source
   */
  class RequestParamsDirectSource extends Http::Server::RequestInputAccess::Range {
    RequestParamsDirectSource() {
      exists(MethodCall request, ElementReference elementRef |
        request instanceof RequestCall and
        elementRef.(ElementReference).getReceiver() = request and
        this.asExpr().getExpr() = elementRef
      )
    }

    override string getSourceType() { result = "request[foo]" }

    override Http::Server::RequestInputKind getKind() { result = "parameter" }
  }

  /**
   * A call to the `request.GET` method to retrieve the query params of the Rack request object.
   */
  class RequestGETCall extends MethodCall {
    RequestGETCall() {
      exists(MethodCall request |
        request instanceof RequestCall and
        this.(MethodCall).getReceiver() = request and
        this.getMethodName() = "GET"
      )
    }
  }

  /**
   * `request.GET[foo]` source
   */
  class RequestGETSource extends Http::Server::RequestInputAccess::Range {
    RequestGETSource() {
      exists(MethodCall get, ElementReference elementRef |
        get instanceof RequestGETCall and
        elementRef.(ElementReference).getReceiver() = get and
        this.asExpr().getExpr() = elementRef
      )
    }

    override string getSourceType() { result = "request.GET[foo]" }

    override Http::Server::RequestInputKind getKind() { result = "parameter" }
  }

  /**
   * A call to the `request.POST` method to retrieve the POST params of the Rack request object.
   */
  class RequestPOSTCall extends MethodCall {
    RequestPOSTCall() {
      exists(MethodCall request |
        request instanceof RequestCall and
        this.(MethodCall).getReceiver() = request and
        this.getMethodName() = "POST"
      )
    }
  }

  /**
   * `request.POST[foo]` source
   */
  class RequestPOSTSource extends Http::Server::RequestInputAccess::Range {
    RequestPOSTSource() {
      exists(MethodCall post, ElementReference elementRef |
        post instanceof RequestPOSTCall and
        elementRef.(ElementReference).getReceiver() = post and
        this.asExpr().getExpr() = elementRef
      )
    }

    override string getSourceType() { result = "request.POST[foo]" }

    override Http::Server::RequestInputKind getKind() { result = "parameter" }
  }
}
// TODO: complete sources e.g. headers (incl cookies, user-agent) (https://www.rubydoc.info/gems/rack/Rack/Request)
