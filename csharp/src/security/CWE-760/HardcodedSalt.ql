/**
 * @name Hardcoded Salt
 * @description Hardcoded Salt
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id cs/hardcoded-salt
 * @tags security
 *       external/cwe/cwe-760
 */

import csharp
private import semmle.code.csharp.frameworks.Moq
private import semmle.code.csharp.dataflow.DataFlow::DataFlow::PathGraph
// import semmle.code.csharp.frameworks.system.security.Cryptography
private import github.Hardcoded
private import github.Cryptography

module HardcodedSalt {
  abstract class Source extends DataFlow::ExprNode { }

  abstract class Sink extends DataFlow::ExprNode { }

  class Hardcoded extends Source {
    Hardcoded() { this instanceof HardcodedValues }
  }

  class HashAlgSalts extends Sink {
    HashAlgSalts() { exists(Cryptography::HashingAlgorithms hash | this = hash.getSalt()) }
  }

  class HardcodedSaltConfiguration extends TaintTracking::Configuration {
    HardcodedSaltConfiguration() { this = "HardcodedSalt" }

    override predicate isSource(DataFlow::Node source) { source instanceof HardcodedSalt::Source }

    override predicate isSink(DataFlow::Node sink) {
      sink instanceof HardcodedSalt::Sink and
      not any(ReturnedByMockObject mock).getAMemberInitializationValue() = sink.asExpr() and
      not any(ReturnedByMockObject mock).getAnArgument() = sink.asExpr()
    }
  }
}

from
  HardcodedSalt::HardcodedSaltConfiguration config, DataFlow::PathNode source,
  DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "hardcoded salt"
