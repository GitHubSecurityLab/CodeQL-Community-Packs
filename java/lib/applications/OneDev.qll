import java
import semmle.code.java.dataflow.FlowSources

class OneDevEditableField extends RemoteFlowSource {
  OneDevEditableField() {
    exists(Method getter, Method setter |
      getter
          .getAnAnnotation()
          .getType()
          .hasQualifiedName("io.onedev.server.web.editable.annotation", "Editable") and
      getter.getDeclaringType() = setter.getDeclaringType() and
      getter.getName().matches("get%") and
      setter.getName().matches("set%") and
      setter.getName().substring(1, setter.getName().length()) =
        getter.getName().substring(1, getter.getName().length()) and
      setter.getAParameter() = this.asParameter()
    )
  }

  override string getSourceType() { result = "OneDev Form Field" }
}
