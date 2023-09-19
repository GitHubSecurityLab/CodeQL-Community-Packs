private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.ApiGraphs

private import github.LocalSources

class XmlParseStringCall extends DataFlow::CallCfgNode {
  XmlParseStringCall() {
    this = API::moduleImport(["xml.etree.ElementTree", "xml.etree.cElementTree"]).getMember("fromString").getACall() or
    this = API::moduleImport(["xml.dom.minidom", "xml.sax"]).getMember("parseString").getACall() or
    this = API::moduleImport("xml.sax").getMember("parseStringIO").getACall()
    or
    this.asCfgNode() = xmlParseStringCall()
  }

  DataFlow::Node getSink() { result = this.getArg(0) } 
}

class XmlParseFileCall extends DataFlow::CallCfgNode {
  XmlParseFileCall() {
    this = API::moduleImport(["xml.etree.ElementTree", "xml.etree.cElementTree", "xml.dom.minidom", "xml.dom.pulldom", "xml.sax"]).getMember("parse").getACall() or
    this = API::moduleImport(["xml.etree.ElementTree", "xml.etree.cElementTree"]).getMember("iterparse").getACall()
    or
    this.asCfgNode() = xmlParseFileCall()
  }

  DataFlow::Node getSink() { result = this.getArg(0) } 

  DataFlow::Node getSource() { result = this.getArg(0) }
}

ControlFlowNode xmlParseFileCall() {
  exists(string method_name, string package_name|
    result = callFromPackage(method_name, package_name)
    and (
      (method_name = "parse" and package_name in ["ElementTree", "cElementTree", "minidom", "pulldom", "sax"])
      or
      (method_name = "interparse" and package_name in ["ElementTree", "cElementTree"])
    )
  )
}

ControlFlowNode xmlParseStringCall() {
  exists(string method_name, string package_name|
    result = callFromPackage(method_name, package_name)
    and (
      (method_name = "parseString" and package_name in ["minidom","sax"])
      or
      (method_name = "parseStringIO" and package_name in ["sax"])
      or
      (method_name = "fromString" and package_name in ["ElementTree", "cElementTree"])
    )
  )
}

ControlFlowNode callFromPackage(string method_name, string package_name) {
  exists(Attribute called_attr, Attribute object |
    result.isCall() and called_attr.getParent() = result.getNode() and
    called_attr.getName() = method_name
    and called_attr.getObject() = object
    and object.getName()  = package_name
  )
}

class LocalUserInput extends DataFlow::Node {
  LocalUserInput() {
    this instanceof LocalSources::Range
  }
}

class UnsafeStringXmlSink extends DataFlow::ExprNode {
  UnsafeStringXmlSink() {
    exists(XmlParseStringCall parse |
      parse.getSink() = this
    )
  }
}

class UnsafeFileXmlSink extends DataFlow::ExprNode {
  UnsafeFileXmlSink() {
    exists(XmlParseFileCall parse |
      parse.getSink() = this
    )
  }
}

class XmlStringConfig extends TaintTracking::Configuration {
  XmlStringConfig() { this = "XMLLocal::XmlStringConfig" }

  override predicate isSource(DataFlow::Node src) { src instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeStringXmlSink }
}

class XmlFileConfig extends TaintTracking::Configuration {
  XmlFileConfig() { this = "XMLLocal::XmlFileConfig" }

  override predicate isSource(DataFlow::Node src) { src instanceof LocalUserInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeFileXmlSink }
}
