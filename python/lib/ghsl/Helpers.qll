import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
// Import Sinks
private import semmle.python.security.dataflow.CommandInjectionCustomizations
private import semmle.python.security.dataflow.CodeInjectionCustomizations
private import semmle.python.security.dataflow.ServerSideRequestForgeryCustomizations
private import semmle.python.security.dataflow.SqlInjectionCustomizations
private import semmle.python.security.dataflow.UnsafeDeserializationCustomizations
// Fields Sinks
private import ghsl.HardcodedSecretSinks
private import ghsl.MassAssignment

// Find Node at Location
predicate findByLocation(DataFlow::Node node, string relative_path, int linenumber) {
  node.getLocation().getFile().getRelativePath() = relative_path and
  node.getLocation().getStartLine() = linenumber
}

// Dangerous Sinks
predicate dangerousSinks(DataFlow::Node sink) {
  (
    sink instanceof CommandInjection::Sink or
    sink instanceof CodeInjection::Sink or
    sink instanceof ServerSideRequestForgery::Sink or
    sink instanceof SqlInjection::Sink or
    sink instanceof UnsafeDeserialization::Sink or
    // Fields Query Addtional Sinks
    sink instanceof CredentialSink or
    sink instanceof MassAssignment::Sinks
  ) and
  sink.getScope().inSource()
}

predicate functionParameters(DataFlow::Node node) {
  (
    // // Function Call Parameters
    node instanceof DataFlow::ParameterNode
    or
    // Function Call Arguments
    node instanceof DataFlow::ArgumentNode
  ) and
  not dangerousSinks(node) and
  node.getScope().inSource()
}
