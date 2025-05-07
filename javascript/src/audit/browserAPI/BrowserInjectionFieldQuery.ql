/**
 * @name Extension API Injection
 * @description Injecting objects with attacker controlled fields into Chrome APIs may result in dangerous side effects.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id js/browserapi-injection-field
 * @tags security
 */


 import javascript
 import ConfigFlow::PathGraph
 import browserextension.BrowserInjectionFieldQuery

   from ConfigFlow::PathNode source, ConfigFlow::PathNode sink
   where ConfigFlow::flowPath(source, sink)
   select sink.getNode(), source, sink, sink.getNode() + " depends on a $@.",
     source.getNode(), "user-provided value"
