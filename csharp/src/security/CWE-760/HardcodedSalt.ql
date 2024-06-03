/**
 * @name Hardcoded Salt
 * @description Hardcoded Salt
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id githubsecuritylab/hardcoded-salt
 * @tags security
 *       external/cwe/cwe-760
 */

import csharp
private import semmle.code.csharp.frameworks.Moq
private import ghsl.Hardcoded
private import ghsl.Cryptography
import HardcodedSalt::Flow::PathGraph

module HardcodedSalt {
  abstract class Source extends DataFlow::ExprNode { }

  abstract class Sink extends DataFlow::ExprNode { }

  class Hardcoded extends Source {
    Hardcoded() { this instanceof HardcodedValues }
  }

  class HashAlgSalts extends Sink {
    HashAlgSalts() { exists(Cryptography::HashingAlgorithms hash | this = hash.getSalt()) }
  }

  module HardcodedSaltConfiguration implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof HardcodedSalt::Source }

    predicate isSink(DataFlow::Node sink) {
      sink instanceof HardcodedSalt::Sink and
      not any(ReturnedByMockObject mock).getAMemberInitializationValue() = sink.asExpr() and
      not any(ReturnedByMockObject mock).getAnArgument() = sink.asExpr()
    }
  }

  module Flow = TaintTracking::Global<HardcodedSaltConfiguration>;
}

from HardcodedSalt::Flow::PathNode source, HardcodedSalt::Flow::PathNode sink
where HardcodedSalt::Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "hardcoded salt"
