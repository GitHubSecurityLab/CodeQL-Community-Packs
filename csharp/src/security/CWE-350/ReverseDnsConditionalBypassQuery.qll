/**
 * Provides a taint-tracking configuration for reasoning about sensitive actions that are
 * guarded by a condition on the result of a reverse DNS lookup (CWE-350).
 *
 * This reuses the sinks and sanitizers of `cs/user-controlled-bypass`, but adds reverse DNS
 * sources that are not modeled there (`Dns.GetHostEntry(IPAddress)` and
 * `Dns.GetHostEntryAsync(IPAddress)`). It also includes `Dns.GetHostByAddress`, whose constant
 * comparison coverage overlaps with the stock query, to detect non-constant host-name comparisons.
 */

import csharp
private import semmle.code.csharp.commons.ComparisonTest
private import semmle.code.csharp.frameworks.system.Net
private import semmle.code.csharp.security.dataflow.ConditionalBypassQuery as ConditionalBypassQuery

/**
 * A call to a `System.Net.Dns` method that performs a reverse DNS lookup of an IP address.
 * The host names in the resulting `IPHostEntry` are controlled by whoever controls the PTR
 * record of that address, so they must not be trusted for security decisions.
 */
class ReverseDnsLookupCall extends MethodCall {
  ReverseDnsLookupCall() {
    exists(SystemNetDnsClass dns, Method m | m = this.getTarget() and m.getDeclaringType() = dns |
      // `GetHostByAddress(string)` and `GetHostByAddress(IPAddress)` are always reverse lookups.
      m = dns.getGetHostByAddressMethod()
      or
      // `GetHostEntry(IPAddress)`, `GetHostEntryAsync(IPAddress)` and their overloads.
      m.hasName(["GetHostEntry", "GetHostEntryAsync"]) and
      m.getParameter(0).getType().(Class).hasFullyQualifiedName("System.Net", "IPAddress")
    )
  }
}

/** A reverse DNS lookup result, which may be controlled by an attacker. */
class ReverseDnsSource extends DataFlow::ExprNode {
  ReverseDnsSource() { this.getExpr() instanceof ReverseDnsLookupCall }
}

/**
 * A taint-tracking configuration for sensitive actions guarded by a condition on
 * the result of a reverse DNS lookup.
 */
private module ReverseDnsConditionalBypassConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ReverseDnsSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ConditionalBypassQuery::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof ConditionalBypassQuery::Sanitizer }

  /**
   * Holds if `pred` is an operand of a comparison `succ`. The default taint steps only
   * propagate through a comparison when the other operand is a constant, but any comparison
   * of a reverse DNS host name (for example against an allow-list held in a variable or a
   * field) is a decision based on reverse DNS.
   */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(ComparisonTest ct |
      ct.getExpr() = succ.asExpr() and
      ct.getAnArgument() = pred.asExpr()
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    result = sink.getLocation()
    or
    result = sink.(ConditionalBypassQuery::Sink).getSensitiveMethodCall().getLocation()
  }
}

/** Taint-tracking flow for sensitive actions guarded by a reverse DNS lookup result. */
module ReverseDnsConditionalBypass = TaintTracking::Global<ReverseDnsConditionalBypassConfig>;
