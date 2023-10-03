/**
 * @name Beam Manipulation
 * @description Bean Manipulation may allow attackers to
 *              execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id githubsecuritylab/bean-manipulation
 * @tags security
 *       external/cwe/cwe-94
 */

import java
import semmle.code.java.dataflow.FlowSources
import BeanManipulationFlow::PathGraph
import ghsl.BeanManipulation

private module BeanManipulationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof BeanManipulationSink }
}

module BeanManipulationFlow = TaintTracking::Global<BeanManipulationConfig>;

from BeanManipulationFlow::PathNode source, BeanManipulationFlow::PathNode sink
where BeanManipulationFlow::flowPath(source, sink)
select sink, source, sink, "Bean Manipulation at $@.", sink.getNode(), "user input"
