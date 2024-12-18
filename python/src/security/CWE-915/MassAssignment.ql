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
import ghsl.MassAssignment::MassAssignment
import MassAssignmentTaint::PathGraph

from MassAssignmentTaint::PathNode source, MassAssignmentTaint::PathNode sink
where MassAssignmentTaint::flowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "mass assignment"
