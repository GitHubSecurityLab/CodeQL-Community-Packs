private import python
private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.frameworks.data.ModelsAsData
private import ghsl

module PromptInjection {
  /**
   * A data flow source for "code injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "code injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "code injection" vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /**
   * A source of remote user input, considered as a flow source.
   */
  class RemoteFlowSourceAsSource extends Source, RemoteFlowSource { }

  /**
   * Models as Data for Prompt Injection
   */
  class PromptInjectionMaD extends Sink {
    PromptInjectionMaD() { this = ModelOutput::getASinkNode("prompt-injection").asSink() }
  }
}
