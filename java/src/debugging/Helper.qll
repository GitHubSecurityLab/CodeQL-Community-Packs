private import semmle.code.java.dataflow.DataFlow
// Sinks
private import semmle.code.java.security.QueryInjection

/**
 * Filter nodes by its location (relative path or base name).
 */
bindingset[relative_path]
predicate findByLocation(DataFlow::Node node, string relative_path, int linenumber) {
  node.getLocation().getFile().getRelativePath().matches(relative_path) and
  node.getLocation().getStartLine() = linenumber
}

/**
 * Find all method accesses by class name.
 * namespace + class name || class name only
 */
bindingset[className]
MethodAccess findAllMethodAccessesByType(string className) {
  exists(RefType rt, MethodAccess ma |
    rt.getQualifiedName() = className
    or
    rt.getName() = className and
    ma.getReceiverType() = rt
  |
    result = ma
  )
}

/**
 * This will only show sinks that are callable (method calls)
 */
predicate isCallable(DataFlow::Node sink) { sink.asExpr() instanceof MethodAccess }

/**
 * Check if the source node is a method parameter.
 */
predicate checkSource(DataFlow::Node source) {
  //   findByLocation(source, "SqlInjectionChallenge.java", _) and
  source.asParameter() instanceof Parameter
  or
  source.asExpr() instanceof MethodAccess
}

/**
 * List of all the sinks that we want to check.
 */
class AllSinks extends DataFlow::Node {
  AllSinks() { this instanceof QueryInjectionSink }
}
