import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs
import ghsl.LocalSources

module MassAssignment {
  abstract class Sources extends DataFlow::Node { }

  abstract class Sinks extends DataFlow::Node { }

  abstract class Sanitizer extends DataFlow::Node { }

  // Setattr build into Python
  class Setattr extends MassAssignment::Sinks {
    Setattr() {
      (
        // > `setattr(obj, SINK, value)`
        this = API::builtin("setattr").getACall().getArg(1)
        or
        // > __setattr__(SINK, value)
        exists(Value value, CallNode call |
          value.getName() = "__setattr__" and
          call = value.getACall() and
          this.asCfgNode() = call.getArg(0)
        )
      ) and
      this.getScope().inSource()
    }
  }

  private module MassAssignmentLocalTaintConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Range }

    predicate isSink(DataFlow::Node sink) { sink instanceof MassAssignment::Sinks }

    predicate isBarrier(DataFlow::Node node) { node instanceof MassAssignment::Sanitizer }
  }

  module MassAssignmentLocalTaint = TaintTracking::Global<MassAssignmentLocalTaintConfig>;

  private module MassAssignmentTaintConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource::Range }

    predicate isSink(DataFlow::Node sink) { sink instanceof MassAssignment::Sinks }

    predicate isBarrier(DataFlow::Node node) { node instanceof MassAssignment::Sanitizer }
  }

  module MassAssignmentTaint = TaintTracking::Global<MassAssignmentTaintConfig>;
}
