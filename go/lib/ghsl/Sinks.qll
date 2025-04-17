private import go
private import semmle.go.dataflow.DataFlow
private import semmle.go.security.CommandInjectionCustomizations
private import semmle.go.security.OpenUrlRedirectCustomizations
private import semmle.go.security.ReflectedXssCustomizations
private import semmle.go.security.RequestForgeryCustomizations
private import semmle.go.security.SqlInjectionCustomizations
private import semmle.go.security.UnsafeUnzipSymlinkCustomizations
private import semmle.go.security.XPathInjectionCustomizations
private import semmle.go.security.ZipSlipCustomizations

/**
 * List of all the sinks that we want to check.
 */
class AllSinks extends DataFlow::Node {
  private string sink;

  AllSinks() {
    this instanceof CommandInjection::Sink and
    sink = "command-injection"
    or
    this instanceof OpenUrlRedirect::Sink and
    sink = "open-url-redirect"
    or
    this instanceof ReflectedXss::Sink and
    sink = "reflected-xss"
    or
    this instanceof RequestForgery::Sink and
    sink = "request-forgery"
    or
    this instanceof SqlInjection::Sink and
    sink = "sql-injection"
    or
    this instanceof UnsafeUnzipSymlink::EvalSymlinksSink and
    sink = "unsafe-unzip"
    or
    this instanceof XPathInjection::Sink and
    sink = "xpath-injection"
    or
    this instanceof ZipSlip::Sink and
    sink = "zip-slip"
  }

  /**
   * Gets the sink sink type.
   */
  string sinkType() { result = sink }
}
