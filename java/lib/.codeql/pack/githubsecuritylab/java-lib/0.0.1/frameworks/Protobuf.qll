import semmle.code.java.dataflow.FlowSources

module Protobuf {
  class ProtoToCoreTaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod().getName().matches("toCore%") and
        n2.asExpr() = ma and
        n1.asExpr() = ma.getArgument(0)
      )
    }
  }

  class ByteStringThisReturnTaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        //ma.getMethod().getName().matches(["toByteArray", "toString", "toStringUtf8", "substring", "concat", "asReadOnlyByteBuffer", "asReadOnlyByteBufferList"]) and
        ma.getMethod().getName().matches("toByteArray") and
        ma.getMethod()
            .getDeclaringType()
            .getASourceSupertype*()
            .(RefType)
            .hasQualifiedName("com.google.protobuf", "ByteString") and
        n1.asExpr() = ma.getQualifier() and
        n2.asExpr() = ma
      )
    }
  }

  class ByteStringArgReturnTaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodAccess ma |
        ma.getMethod().getName().matches(["readFrom", "copyFrom", "concat"]) and
        ma.getMethod()
            .getDeclaringType()
            .getASourceSupertype*()
            .(RefType)
            .hasQualifiedName("com.google.protobuf", "ByteString") and
        n1.asExpr() = ma.getArgument(0) and
        n2.asExpr() = ma
      )
    }
  }

  class RemoteSource extends RemoteFlowSource {
    RemoteSource() {
      exists(MethodAccess ma, Method m |
        ma.getMethod() = m and
        m.getName().matches("get%") and
        m.getDeclaringType()
            .getASourceSupertype*()
            .(RefType)
            .hasQualifiedName("com.google.protobuf", "GeneratedMessageV3") and
        this.asExpr() = ma
      )
    }

    override string getSourceType() { result = "Protobuf Source" }
  }
}
