import java
import semmle.code.java.frameworks.javaee.ejb.EJBRestrictions
import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

abstract class Source extends DataFlow::Node {
  Source() { this = this }
}

module RuntimeExec {
  // a static string of an unsafe executable tainting arg 0 of Runtime.exec()
  module RuntimeExecConfiguration implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
      source.asExpr() instanceof StringLiteral and
      source.asExpr().(StringLiteral).getValue() instanceof UnSafeExecutable
    }

    predicate isSink(DataFlow::Node sink) {
      exists(RuntimeExecMethod method, MethodCall call |
        call.getMethod() = method and
        sink.asExpr() = call.getArgument(0) and
        sink.asExpr().getType() instanceof Array
      )
    }

    predicate isBarrier(DataFlow::Node node) {
      node.asExpr().getFile().isSourceFile() and
      (
        node instanceof AssignToNonZeroIndex or
        node instanceof ArrayInitAtNonZeroIndex or
        node instanceof StreamConcatAtNonZeroIndex or
        node.getType() instanceof PrimitiveType or
        node.getType() instanceof BoxedType
      )
    }
  }

  module RuntimeExecFlow = TaintTracking::Global<RuntimeExecConfiguration>;

  import RuntimeExecFlow::PathGraph
}

// taint flow from user data to args of the command
module ExecTaint {
  module ExecTaintConfiguration implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof Source }

    predicate isSink(DataFlow::Node sink) {
      exists(RuntimeExecMethod method, MethodCall call, int index |
        call.getMethod() = method and
        sink.asExpr() = call.getArgument(index) and
        sink.asExpr().getType() instanceof Array
      )
    }

    predicate isBarrier(DataFlow::Node node) {
      node.asExpr().getFile().isSourceFile() and
      (
        node.getType() instanceof PrimitiveType or
        node.getType() instanceof BoxedType
      )
    }
  }

  module ExecTaintFlow = TaintTracking::Global<ExecTaintConfiguration>;

  import ExecTaintFlow::PathGraph
}

// array[3] = node
class AssignToNonZeroIndex extends DataFlow::Node {
  AssignExpr assign;
  ArrayAccess access;

  AssignToNonZeroIndex() {
    assign.getDest() = access and
    access.getIndexExpr().(IntegerLiteral).getValue() != "0" and
    assign.getSource() = this.asExpr()
  }
}

// String[] array = {"a", "b, "c"};
class ArrayInitAtNonZeroIndex extends DataFlow::Node {
  ArrayInit init;
  int index;

  ArrayInitAtNonZeroIndex() {
    init.getInit(index) = this.asExpr() and
    index != 0
  }
}

// Stream.concat(Arrays.stream(array_1), Arrays.stream(array_2))
class StreamConcatAtNonZeroIndex extends DataFlow::Node {
  MethodCall call;
  int index;

  StreamConcatAtNonZeroIndex() {
    call.getMethod().getQualifiedName() = "java.util.stream.Stream.concat" and
    call.getArgument(index) = this.asExpr() and
    index != 0
  }
}

// allow list of executables that execute their arguments
// TODO: extend with data extensions
class UnSafeExecutable extends string {
  bindingset[this]
  UnSafeExecutable() {
    this.regexpMatch("^(|.*/)([a-z]*sh|javac?|python[23]?|perl|[Pp]ower[Ss]hell|php|node|deno|bun|ruby|osascript|cmd|Rscript|groovy)(\\.exe)?$") and
    not this.matches("netsh.exe")
  }
}
