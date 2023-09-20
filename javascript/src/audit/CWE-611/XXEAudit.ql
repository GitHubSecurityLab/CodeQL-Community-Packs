/**
 * @name Audit: XML External Entity sink used
 * @description A XML External Entity (XXE) sink is being used in your application
 * @kind problem
 * @problem.severity error
 * @security-severity 3.0
 * @id githubsecuritylab/audit/xxe
 * @tags security
 *       external/cwe/cwe-611
 *       audit
 */

import javascript
private import semmle.javascript.security.dataflow.XxeCustomizations

from DataFlow::Node sink
where sink instanceof Xxe::Sink
select sink, "XML External Entity sink"
