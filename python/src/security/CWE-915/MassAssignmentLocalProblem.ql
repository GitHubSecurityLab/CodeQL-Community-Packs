/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.0
 * @precision high
 * @sub-severity high
 * @id githubsecuritylab/mass-assignment-problem-local
 * @tags security
 *       external/cwe/cwe-2915
 *       local
 *       testing
 */

import python
import github.MassAssignment

from MassAssignment::MassAssignmentLocalConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Use of $@.", source, "mass assignment"
