/**
 * @name Browser request forgery
 * @description Making a client-to-server request with user-controlled data in the URL allows a request forgery attack
 *              against the client.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 5.0
 * @precision medium
 * @id js/client-side-request-forgery
 * @tags security
 *       external/cwe/cwe-918
 */

 import javascript
 import browserextension.BothSidesRequestForgeryQuery
 import ConfigFlow::PathGraph
 
 from ConfigFlow::PathNode source, ConfigFlow::PathNode sink, DataFlow::Node request
 where
   ConfigFlow::flowPath(source, sink) and
   request = sink.getNode().(Sink).getARequest()
 select request, source, sink, "The $@ of this request depends on a $@.", sink.getNode(),
   sink.getNode().(Sink).getKind(), source, "user-provided value"