/**
 * Test that the standard `java/sql-injection` query (`QueryInjectionFlow`,
 * from `semmle.code.java.security.SqlInjectionQuery`) recognizes taint
 * reaching the Spring R2DBC (`org.springframework.r2dbc.core.DatabaseClient`)
 * and raw R2DBC SPI (`io.r2dbc.spi`) sinks modeled in
 * `java/ext/manual/org.springframework.r2dbc.model.yml` and
 * `java/ext/manual/io.r2dbc.spi.model.yml`.
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery

/**
 * A fake remote flow source used by the test code to mark a value as
 * tainted, matching calls to a `source()` method. This isolates the test
 * from real-world remote-flow-source modeling (e.g. `@RequestParam`) so it
 * focuses purely on validating the new sink models.
 */
private class SourceMethodSource extends RemoteFlowSource {
  SourceMethodSource() { this.asExpr().(MethodCall).getMethod().hasName("source") }

  override string getSourceType() { result = "source" }
}

from DataFlow::Node source, DataFlow::Node sink
where QueryInjectionFlow::flow(source, sink)
select source, sink
