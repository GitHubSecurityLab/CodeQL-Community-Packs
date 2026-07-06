/**
 * @name Record retrieval using a user-controlled identifier
 * @description A request-controlled identifier flows into a data-access lookup
 *              with no per-record ownership or authorization check, so an
 *              attacker may read another user's record by changing the
 *              identifier. This is the read/disclosure sub-class of insecure
 *              direct object reference (IDOR). It is a heuristic; review each
 *              result for an ownership check on the returned record.
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @id githubsecuritylab/java/user-controlled-record-retrieval
 * @tags security
 *       external/cwe/cwe-639
 *       external/cwe/cwe-863
 */

import java
import semmle.code.java.dataflow.TaintTracking
import RecordRetrievalFlow::PathGraph

/** A Spring MVC handler-method parameter bound from the request path. */
class PathVariableParam extends Parameter {
  PathVariableParam() {
    this.getAnAnnotation()
        .getType()
        .hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable")
  }
}

/** A call to a Spring Data style repository finder that looks a record up by id. */
class RepositoryFindByIdCall extends MethodCall {
  Expr idArg;

  RepositoryFindByIdCall() {
    this.getMethod().hasName(["findById", "getById", "getOne", "findOne", "getReferenceById"]) and
    idArg = this.getArgument(0)
  }

  Expr getIdArg() { result = idArg }
}

module RecordRetrievalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asParameter() instanceof PathVariableParam }

  predicate isSink(DataFlow::Node sink) {
    exists(RepositoryFindByIdCall c | sink.asExpr() = c.getIdArg())
  }
}

module RecordRetrievalFlow = TaintTracking::Global<RecordRetrievalConfig>;

from RecordRetrievalFlow::PathNode source, RecordRetrievalFlow::PathNode sink
where RecordRetrievalFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Record is retrieved by request-controlled id from $@ with no per-record authorization check (possible read IDOR).",
  source.getNode(), "this path variable"
