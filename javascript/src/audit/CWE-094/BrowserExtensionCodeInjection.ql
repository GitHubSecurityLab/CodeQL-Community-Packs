/**
 * @name Browser code injection
 * @description Interpreting unsanitized user input as code allows a malicious external entity arbitrary
 *              code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id js/browser-code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

 import javascript
 import browserextension.CodeInjectionQuery
 import ConfigFlow::PathGraph
 
 from ConfigFlow::PathNode source, ConfigFlow::PathNode sink
 where ConfigFlow::flowPath(source, sink)
 select sink.getNode(), source, sink, sink.getNode().(Sink).getMessagePrefix() + " depends on a $@.",
   source.getNode(), "user-provided value"