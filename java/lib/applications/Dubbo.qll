import java
import semmle.code.java.dataflow.FlowSteps
import semmle.code.java.dataflow.FlowSources

module Dubbo {
  class ConfigListener extends RemoteFlowSource {
    ConfigListener() {
      exists(Method m, Parameter p, Interface c |
        this.asParameter() = p and
        m.getAParameter() = p and
        m.isPublic() and
        c = m.getDeclaringType().getASourceSupertype*() and
        c.getName() = ["NotifyListener", "ConfigurationListener"] and
        m.overridesOrInstantiates(c.getAMethod()) and
        not m.getDeclaringType().getLocation().getFile().getAbsolutePath().matches("%/src/test/%")
      )
    }

    override string getSourceType() { result = "Config Listener Source" }
  }

  class CodecSupportGetPayload extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod()
            .getDeclaringType()
            .hasQualifiedName("org.apache.dubbo.remoting.transport", "CodecSupport") and
        ma.getMethod().hasName("getPayload") and
        n1.asExpr() = ma.getArgument(0) and
        n2.asExpr() = ma
      )
    }
  }

  class CodecSupportDeserialize extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod()
            .getDeclaringType()
            .hasQualifiedName("org.apache.dubbo.remoting.transport", "CodecSupport") and
        ma.getMethod().hasName("deserialize") and
        n1.asExpr() = ma.getArgument(1) and
        n2.asExpr() = ma
      )
    }
  }

  class ChannelBufferInputStreamInit extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(ClassInstanceExpr ma |
        ma.getConstructedType()
            .hasQualifiedName("org.apache.dubbo.remoting.buffer", "ChannelBufferInputStream") and
        n1.asExpr() = ma.getArgument(0) and
        n2.asExpr() = ma
      )
    }
  }

  class ChannelBuffer_ThisReturn_TaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod()
            .getDeclaringType()
            .getASourceSupertype*()
            .hasQualifiedName("org.apache.dubbo.remoting.buffer", "ChannelBuffer") and
        ma.getMethod().getName().matches(["array", "getByte", "readByte", "toByteBuffer"]) and
        n1.asExpr() = ma.getQualifier() and
        n2.asExpr() = ma
      )
    }
  }

  class ChannelBuffer_ThisArg1_TaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod()
            .getDeclaringType()
            .getASourceSupertype*()
            .hasQualifiedName("org.apache.dubbo.remoting.buffer", "ChannelBuffer") and
        ma.getMethod().getName().matches("getBytes") and
        n1.asExpr() = ma.getQualifier() and
        n2.asExpr() = ma.getArgument(1)
      )
    }
  }

  class ChannelBuffer_ThisArg0_TaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod()
            .getDeclaringType()
            .getASourceSupertype*()
            .hasQualifiedName("org.apache.dubbo.remoting.buffer", "ChannelBuffer") and
        ma.getMethod().getName().matches("readBytes") and
        n1.asExpr() = ma.getQualifier() and
        n2.asExpr() = ma.getArgument(0)
      )
    }
  }

  class ChannelBuffer_ArgThis1_TaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod()
            .getDeclaringType()
            .getASourceSupertype*()
            .hasQualifiedName("org.apache.dubbo.remoting.buffer", "ChannelBuffer") and
        ma.getMethod().getName().matches("setBytes") and
        n1.asExpr() = ma.getArgument(1) and
        n2.asExpr() = ma.getQualifier()
      )
    }
  }

  class ChannelBuffer_ArgThis0_TaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod()
            .getDeclaringType()
            .getASourceSupertype*()
            .hasQualifiedName("org.apache.dubbo.remoting.buffer", "ChannelBuffer") and
        ma.getMethod().getName().matches("writeBytes") and
        n1.asExpr() = ma.getArgument(1) and
        n2.asExpr() = ma.getQualifier()
      )
    }
  }
}
