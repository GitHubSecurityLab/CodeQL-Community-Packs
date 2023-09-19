private import python

private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.dataflow.new.RemoteFlowSources

private import github.LocalSources

class FormatStringTaintConfiguration extends TaintTracking::Configuration {
    FormatStringTaintConfiguration() { this = "FormatStringTaintConfiguration" }
    
    override predicate isSource(DataFlow::Node source) {
        source instanceof RemoteFlowSource
        or
        source instanceof LocalSources::Range
    }
    
    override predicate isSink(DataFlow::Node sink) {
        sink instanceof FormatString
        and not sink.asExpr() instanceof StrConst
    }
}

class FormatString extends DataFlow::Node {
    FormatString() {
        exists(CallNode call |
            call.getFunction().(AttrNode).getName() = "format"
            and call.getFunction().(AttrNode).getObject() = this.asCfgNode()
        )
    }
}
