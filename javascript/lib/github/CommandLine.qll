import semmle.javascript.dataflow.DataFlow

class CommandLineArgument extends DataFlow::Node {
    CommandLineArgument() {
        this = DataFlow::globalVarRef("process").getAPropertyRead("argv").getAPropertyReference()
    }
}
