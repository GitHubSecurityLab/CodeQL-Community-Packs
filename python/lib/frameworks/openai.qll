private import python
private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.frameworks.data.ModelsAsData
// LLM
private import ghsl.llm.Injection

module OpenAI {
  module AzureOpenAI {
    API::Node classRef() {
      result =
        API::moduleImport("openai")
            .getMember(["BaseAzureClient", "AzureOpenAI", "AsyncAzureOpenAI"])
            .getASubclass*()
    }

    API::Node instance() { result = classRef().getReturn() }
  }

  class OpenAISinks extends PromptInjection::Sink {
    // AzureOpenAI.chat.completions.with_raw_response.create
    OpenAISinks() {
      this =
        OpenAI::AzureOpenAI::instance()
            .getMember("chat")
            .getMember("completions")
            .getMember("with_raw_response")
            .getMember("create")
            .getACall()
    }
  }
}
