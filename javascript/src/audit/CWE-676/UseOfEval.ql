/**
 * @name Audit: Using JS Eval
 * @description Usage of eval in JavaScript / TypeScript can be dangerous
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 2.0
 * @id githubsecuritylab/audit/using-eval
 * @tags maintainability
 *       external/cwe/cwe-676
 *       audit
 */

import javascript
import semmle.javascript.security.dataflow.CodeInjectionCustomizations

from CodeInjection::EvalJavaScriptSink eval
select eval, "Using eval"
