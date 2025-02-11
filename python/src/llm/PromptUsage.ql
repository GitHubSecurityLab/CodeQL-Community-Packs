/**
 * @name AI Prompt Usage
 * @description AI Prompt Usage
 * @kind problem
 * @problem.severity error
 * @security-severity 2.0
 * @sub-severity medium
 * @precision medium
 * @id githubsecuritylab/prompt-usage
 * @tags security
 */

import python
import ghsl.llm.Injection

from PromptInjection::Sink sinks
select sinks, "AI prompt used"
