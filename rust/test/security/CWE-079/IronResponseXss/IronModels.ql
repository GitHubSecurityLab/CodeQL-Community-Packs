/**
 * Tests the Iron data extension rows: the request passed to a handler is a remote source, and the
 * argument of `Response::with` is an HTML injection sink.
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.FlowSink
import codeql.rust.dataflow.FlowSource

from DataFlow::Node node, string kind
where
  sourceNode(node, "remote") and kind = "remote source"
  or
  sinkNode(node, "html-injection") and kind = "html-injection sink"
select node, kind
