/**
 * Additional sinks that are not yet covered by CodeQL's rails sinks.
 * Ruby on Rails adds methods to the Object class.
 * In the case of the `try/try!` methods this looks like this (see try.rb):
 * 
 * class Object
 *      include ActiveSupport::Tryable
 * 
 * ref: https://api.rubyonrails.org/classes/Object.html
 */

private import codeql.ruby.AST
private import codeql.ruby.Concepts
private import codeql.ruby.DataFlow

module RailsAddonSinks {

  class RailsTryCodeExecution extends CodeExecution::Range, DataFlow::CallNode {
    RailsTryCodeExecution() { this.getMethodName() = ["try", "try!"] }

    override DataFlow::Node getCode() { result = this.getArgument(0) }
  }
}
