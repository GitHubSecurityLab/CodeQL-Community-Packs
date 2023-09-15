import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2

module Base64 {
  abstract class Encoding extends DataFlow::Node { }

  abstract class Decoding extends DataFlow::Node { }

  // codeql/java/ql/lib/semmle/code/java/security/HardcodedCredentialsApiCallQuery.qll
  class Encoders extends Base64::Encoding {
    Encoders() {
      exists(MethodAccess ma |
        ma.getMethod()
            .hasQualifiedName([
                "java.util", "cn.hutool.core.codec", "org.apache.shiro.codec",
                "apache.commons.codec.binary", "org.springframework.util"
              ], ["Base64$Encoder", "Base64", "Base64Utils"],
              [
                "encode", "encodeToString", "encodeBase64", "encodeBase64Chunked",
                "encodeBase64String", "encodeBase64URLSafe", "encodeBase64URLSafeString"
              ])
      |
        this.asExpr() = ma.getArgument(0)
      )
    }
  }

  class Decoders extends Base64::Decoding {
    Decoders() {
      exists(MethodAccess ma |
        ma.getMethod()
            .hasQualifiedName([
                "java.util", "cn.hutool.core.codec", "org.apache.shiro.codec",
                "apache.commons.codec.binary", "org.springframework.util"
              ], ["Base64$Decoder", "Base64", "Base64Utils"], ["decode", "decodeBase64"])
      |
        this.asExpr() = ma.getArgument(0)
      )
    }
  }
}
