/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 2.0
 * @precision high
 * @sub-severity high
 * @id githubsecuritylab/mass-assignment-local
 * @tags security
 *       local
 *       external/cwe/cwe-2915
 */

import python
import ghsl.MassAssignment::MassAssignment
import MassAssignmentLocalTaint::PathGraph

from MassAssignmentLocalTaint::PathNode source, MassAssignmentLocalTaint::PathNode sink
where MassAssignmentLocalTaint::flowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "mass assignment"
