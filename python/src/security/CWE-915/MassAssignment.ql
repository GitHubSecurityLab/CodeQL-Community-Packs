/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @sub-severity high
 * @id githubsecuritylab/mass-assignment
 * @tags security
 *       external/cwe/cwe-2915
 */

import python
import DataFlow::PathGraph
import ghsl.MassAssignment

from MassAssignment::MassAssignmentConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "mass assignment"
