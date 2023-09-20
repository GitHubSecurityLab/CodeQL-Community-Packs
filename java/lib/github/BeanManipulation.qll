private import semmle.code.java.dataflow.TaintTracking

class SetPropertyMethod extends Method {
  SetPropertyMethod() {
    this.getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName("org.springframework.beans", "PropertyAccessor") and
    this.hasName(["setPropertyValue", "setPropertyValues"])
    or
    this.getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName(["org.apache.commons.beanutils", "org.apache.commons.beanutils2"],
          ["PropertyUtils", "PropertyUtilsBean"]) and
    this.hasName(["setProperty", "setNestedProperty", "setSimpleProperty"])
    or
    this.getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName(["org.apache.commons.beanutils", "org.apache.commons.beanutils2"],
          ["BeanUtils", "BeanUtilsBean"]) and
    this.hasName(["setProperty", "populate"])
    or
    this.getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName("org.springframework.data.redis.hash", "BeanUtilsHashMapper") and
    this.hasName("fromHash")
    or
    this.getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName("org.springframework.beans",
          "AbstractNestablePropertyAccessor$PropertyHandler") and
    this.hasName("setValue")
    or
    this.getDeclaringType()
        .getASourceSupertype*()
        .hasQualifiedName("org.springframework.beans",
          ["AbstractNestablePropertyAccessor", "AbstractPropertyAccessor"]) and
    this.hasName(["setPropertyValue", "setPropertyValues"])
  }
}

class BeanManipulationSink extends DataFlow::ExprNode {
  BeanManipulationSink() {
    exists(MethodAccess ma |
      ma.getMethod() instanceof SetPropertyMethod and
      this.getExpr() = ma.getAnArgument()
    )
  }
}
