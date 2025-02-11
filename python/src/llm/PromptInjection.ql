/**
 * @name Prompt Injection
 * @description Prompt injection vulnerabilities occur when a program uses user input to generate prompts or messages. If the user input is not properly sanitized, an attacker can inject malicious code into the prompt, leading to command injection or other attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @sub-severity high
 * @precision high
 * @id githubsecuritylab/prompt-injection
 * @tags security
 *       llm
 *       external/owasp-ml-2023/ML01
 */

import python
import ghsl
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// LLM
import ghsl.llm.Injection

private module PromptInjectionConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof PromptInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof PromptInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof PromptInjection::Sanitizer }
}

module PromptInjectionFlows = TaintTracking::Global<PromptInjectionConfiguration>;

import PromptInjectionFlows::PathGraph

from PromptInjectionFlows::PathNode source, PromptInjectionFlows::PathNode sink
where PromptInjectionFlows::flowPath(source, sink)
select sink.getNode(), source, sink, "This prompt depends on $@.", source.getNode(),
  "a user-provided value"
