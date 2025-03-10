/**
 * @name ProcessName to hash function flow
 * @description Flow from a function retrieving process name to a hash function.
 * @kind path-problem
 * @tags security
 *       solorigate
 * @problem.severity warning
 * @precision medium
 * @id githubsecuritylab/cs/backdoor/process-name-to-hash-function
 */

import csharp
import experimental.code.csharp.Cryptography.NonCryptographicHashes
import DataFlowFromMethodToHash::PathGraph

module DataFlowFromMethodToHashConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isSuspiciousPropertyName(source.asExpr()) }

  predicate isSink(DataFlow::Node sink) { isGetHash(sink.asExpr()) }
}

module DataFlowFromMethodToHash = TaintTracking::Global<DataFlowFromMethodToHashConfig>;

predicate isGetHash(Expr arg) {
  exists(MethodCall mc |
    (
      mc.getTarget().getName().matches("%Hash%") or
      mc.getTarget().getName().regexpMatch("Md[4-5]|Sha[1-9]{1,3}")
    ) and
    mc.getAnArgument() = arg
  )
  or
  exists(Callable callable, Parameter param, Call call |
    isCallableAPotentialNonCryptographicHashFunction(callable, param) and
    call = callable.getACall() and
    arg = call.getArgumentForParameter(param)
  )
}

predicate isSuspiciousPropertyName(PropertyRead pr) {
  pr.getTarget().hasFullyQualifiedName("System.Diagnostics", "Process", "ProcessName")
}

from DataFlowFromMethodToHash::PathNode src, DataFlowFromMethodToHash::PathNode sink
where DataFlowFromMethodToHash::flow(src.getNode(), sink.getNode())
select src.getNode(), src, sink,
  "The hash is calculated on $@, may be related to a backdoor. Please review the code for possible malicious intent.",
  sink.getNode(), "this process name"
