/**
 * @name Mass assignment
 * @description Experimental query to inspect the object graph of types bound from a request
 * @kind path-problem
 * @id githubsecuritylab/mass-assignment
 * @problem.severity error
 * @tags security
 *       external/cwe/cwe-915
 */

import java
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.frameworks.JaxWS

/**
 * A class that is unmarshalled from an HTTP request
 */
class RequestBoundType extends RefType {
  Method controllerMethod;

  RequestBoundType() {
    exists(SpringRequestMappingParameter p |
      p.isTaintedInput() and
      this = getBaseType*(p.getType()) and
      controllerMethod.getAParameter() = p
    )
    or
    exists(JaxRsResourceClass service, Parameter p |
      service.getAnInjectableCallable().getAParameter() = p and
      this = getBaseType*(p.getType()) and
      controllerMethod.getAParameter() = p
    )
  }

  Method getControllerMethod() { result = controllerMethod }
}

/**
 * Base type for a given type
 */
Type getBaseType(RefType orig) {
  if orig instanceof Array
  then result = orig.(Array).getElementType()
  else
    if orig instanceof ParameterizedType
    then result = orig.(ParameterizedType).getATypeArgument()
    else result = orig
}

/**
 * Holds if it is possible to get an instance of t2 from a t1 property
 */
query predicate edges(RefType t1, RefType t2) {
  exists(GetterMethod getter, Field f |
    t1.getAMethod() = getter and
    getter.isPublic() and
    getter.getField() = f and
    //t2 = getBaseType*(f.getType())
    (
      t2 = getBaseType*(f.getType().(RefType).getASupertype*()) or
      t2 = getBaseType*(f.getType().(RefType).getASubtype*())
    )
  ) and
  not t2 instanceof BoxedType and
  not t2 instanceof TypeString and
  not t2 instanceof TypeObject and
  not t2 instanceof Interface and
  not t2.isAbstract()
}

from RequestBoundType root, RefType t, Field f
where
  edges+(root, t) and
  f = t.getAField() and
  f.getName().toLowerCase().regexpMatch(".*(admin|tax|rating).*")
select t, root, t, "$@ field reachable from $@", f, f.getName(), root.getControllerMethod(),
  root.getControllerMethod().getName()
