private import python
private import semmle.python.ApiGraphs
private import semmle.python.Concepts
private import semmle.python.dataflow.new.DataFlow

private import semmle.python.security.dataflow.SqlInjectionCustomizations
private import semmle.python.security.dataflow.CodeInjectionCustomizations
private import semmle.python.security.dataflow.CommandInjectionCustomizations
private import semmle.python.security.dataflow.LdapInjectionCustomizations
private import semmle.python.security.dataflow.NoSqlInjectionCustomizations
private import semmle.python.security.dataflow.ReflectedXSSCustomizations
private import semmle.python.security.dataflow.UnsafeDeserializationCustomizations
private import semmle.python.security.dataflow.XpathInjectionCustomizations
private import semmle.python.security.dataflow.XxeCustomizations
// Fields Sinks
private import ghsl.HardcodedSecretSinks
private import ghsl.MassAssignment


/**
 * List of all the sinks that we want to check.
 */
class AllSinks extends DataFlow::Node {
  private string sink;

  AllSinks() {
    this instanceof MassAssignment::Sinks and
    sink = "mass-assignment"
    or
    this instanceof CredentialSink and
    sink = "credential"
    or
    this instanceof SqlInjection::Sink and
    sink = "sql-injection"
    or
    this instanceof CodeInjection::Sink and
    sink = "code-injection"
    or
    this instanceof CommandInjection::Sink and
    sink = "command-injection"
    or
    (
      this instanceof LdapInjection::DnSink
      or
      this instanceof LdapInjection::FilterSink
    ) and
    sink = "ldap-injection"
    or
    (
      this instanceof NoSqlInjection::NoSqlExecutionAsDictSink and
      this instanceof NoSqlInjection::NoSqlExecutionAsStringSink
    ) and
    sink = "nosql-injection"
    or
    this instanceof ReflectedXss::Sink and
    sink = "reflected-xss"
    or
    this instanceof UnsafeDeserialization::Sink and
    sink = "unsafe-deserialization"
    or
    this instanceof XpathInjection::Sink and
    sink = "xpath-injection"
    or
    this instanceof Xxe::Sink and
    sink = "xxe"
  }

  /**
   * Gets the sink sink type.
   */
  string sinkType() { result = sink }
}