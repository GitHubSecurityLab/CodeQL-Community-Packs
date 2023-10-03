/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @sub-severity high
 * @id githubsecuritylab/mass-assignment-problem
 * @tags security
 *       external/cwe/cwe-2915
 *       testing
 *       local
 */

import python
import ghsl.MassAssignment

from MassAssignment::MassAssignmentConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Use of $@.", source, "mass assignment"
