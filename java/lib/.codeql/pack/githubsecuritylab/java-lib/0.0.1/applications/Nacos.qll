import java
import semmle.code.java.dataflow.FlowSources

class GrpcRequest extends RemoteFlowSource {
  GrpcRequest() {
    exists(Method m |
      m.getName() = "handleRequest" and
      m.getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("com.alipay.sofa.jraft.rpc", "RpcProcessor") and
      m.getParameter(1) = this.asParameter()
    )
  }

  override string getSourceType() { result = "gRPC Form Field" }
}
