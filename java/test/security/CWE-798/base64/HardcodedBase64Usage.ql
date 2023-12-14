import java
import semmle.code.java.security.HardcodedCredentials
import ghsl.Encoding
import ghsl.Hardcoded

query predicate sources(DataFlow::Node sources) {
  sources instanceof Hardcoded
}

query predicate sinks(DataFlow::Node sinks) {
  sinks instanceof Base64::Decoding
}
