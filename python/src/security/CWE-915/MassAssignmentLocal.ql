/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 2.0
 * @precision high
 * @sub-severity high
 * @id py/mass-assignment
 * @tags security
 *       local
 *       external/cwe/cwe-2915
 */

import python
import DataFlow::PathGraph
import github.MassAssignment

from
  MassAssignment::MassAssignmentLocalConfig config, DataFlow::PathNode source,
  DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "mass assignment"
