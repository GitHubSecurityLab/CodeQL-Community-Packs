/**
 * @name XML parser explicitly configured to resolve external entities
 * @description An XML parser that is explicitly configured to process DTDs and to use an
 *              unrestricted `XmlResolver` resolves external entities, which allows local file
 *              disclosure and server-side request forgery (XXE) if the XML is attacker-controlled.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.1
 * @precision medium
 * @id githubsecuritylab/cs/explicit-insecure-dtd-resolver
 * @tags security
 *       experimental
 *       external/cwe/cwe-611
 *       external/cwe/cwe-827
 */

import csharp

/** Holds if `e` is a value for `XmlResolver` that does not restrict external entity resolution. */
predicate isUnrestrictedResolver(Expr e) {
  exists(Expr value |
    DataFlow::localExprFlow(value, e) and
    not (value = e and e instanceof LocalVariableAccess) and
    not value instanceof NullLiteral and
    not value.getType().(RefType).hasFullyQualifiedName("System.Xml", "XmlSecureResolver") and
    value.getType().(RefType).getABaseType*().hasFullyQualifiedName("System.Xml", "XmlResolver")
  )
}

/** Holds if `e` is a value for `DtdProcessing` that enables DTD processing. */
predicate isDtdParse(Expr e) {
  e.(FieldAccess).getTarget().(EnumConstant).hasName("Parse") and
  e.getType().(Enum).hasFullyQualifiedName("System.Xml", "DtdProcessing")
}

/** Holds if `e` is a value for `DtdProcessing` or `ProhibitDtd` that disables DTD processing. */
predicate isDtdDisabled(Expr e) {
  e.(FieldAccess).getTarget().(EnumConstant).hasName(["Prohibit", "Ignore"]) and
  e.getType().(Enum).hasFullyQualifiedName("System.Xml", "DtdProcessing")
  or
  e.(BoolLiteral).getBoolValue() = true
}

/** An object creation of `XmlReaderSettings` or `XmlTextReader`, whose properties configure a parser. */
class XmlParserConfigCreation extends ObjectCreation {
  XmlParserConfigCreation() {
    this.getObjectType().hasFullyQualifiedName("System.Xml", ["XmlReaderSettings", "XmlTextReader"])
  }
}

/** Holds if `write` assigns `prop` on the object created by `create`. */
private predicate writesProperty(XmlParserConfigCreation create, string prop, AssignExpr write) {
  exists(MemberInitializer init |
    init = write and
    init = create.getInitializer().(ObjectInitializer).getAMemberInitializer() and
    init.getLeftOperand().(PropertyAccess).getTarget().hasName(prop)
  )
  or
  exists(PropertyAccess access |
    access = write.getLeftOperand() and
    DataFlow::localExprFlow(create, access.getQualifier()) and
    access.getTarget().hasName(prop)
  )
}

/** Holds if `write` assigns one of the properties that control DTD processing. */
private predicate writesDtdProperty(XmlParserConfigCreation create, AssignExpr write) {
  writesProperty(create, ["DtdProcessing", "ProhibitDtd"], write)
}

/**
 * Holds if `later` follows `write`, both writes to a property of the object created by `create`.
 * In the same basic block only the order of the writes counts, so that a loop back edge does
 * not make each of them follow the other.
 */
private predicate followsWrite(XmlParserConfigCreation create, AssignExpr write, AssignExpr later) {
  writesProperty(create, _, write) and
  writesProperty(create, _, later) and
  (
    exists(BasicBlock bb, int i, int j |
      bb.getNode(i) = write.getControlFlowNode() and
      bb.getNode(j) = later.getControlFlowNode() and
      i < j
    )
    or
    later.getBasicBlock() = write.getBasicBlock().getASuccessor+() and
    later.getBasicBlock() != write.getBasicBlock()
  )
}

/**
 * Gets a value assigned to property `prop` of the object created by `create` that is not
 * overwritten before `end`.
 */
Expr getAValueForProp(XmlParserConfigCreation create, string prop, ControlFlowElement end) {
  exists(AssignExpr write |
    writesProperty(create, prop, write) and
    end.reachableFrom(write) and
    not exists(AssignExpr later |
      writesProperty(create, prop, later) and
      followsWrite(create, write, later) and
      end.reachableFrom(later)
    ) and
    result = write.getRightOperand()
  )
}

/**
 * Gets a value assigned to `DtdProcessing` or `ProhibitDtd` of the object created by `create`
 * that is not overwritten by either property before `end`.
 */
Expr getAValueForDtdProp(XmlParserConfigCreation create, ControlFlowElement end) {
  exists(AssignExpr write |
    writesDtdProperty(create, write) and
    end.reachableFrom(write) and
    not exists(AssignExpr later |
      writesDtdProperty(create, later) and
      followsWrite(create, write, later) and
      end.reachableFrom(later)
    ) and
    result = write.getRightOperand()
  )
}

/**
 * Gets a point at which the configuration of `create` is observed: a call to `XmlReader.Create`
 * in the same callable, or a return of the object created by `create`.
 */
private ControlFlowElement getAConfigurationEnd(XmlParserConfigCreation create) {
  result.(XmlReaderCreateCall).getEnclosingCallable() = create.getEnclosingCallable()
  or
  exists(ReturnStmt ret |
    ret.getEnclosingCallable() = create.getEnclosingCallable() and
    DataFlow::localExprFlow(create, ret.getExpr()) and
    result = ret
  )
}

/** Holds if `settings` explicitly enables DTD processing and an unrestricted resolver at `end`. */
predicate insecureSettings(
  XmlParserConfigCreation settings, ControlFlowElement end, Expr dtd, Expr resolver
) {
  settings.getObjectType().hasFullyQualifiedName("System.Xml", "XmlReaderSettings") and
  end = getAConfigurationEnd(settings) and
  resolver = getAValueForProp(settings, "XmlResolver", end) and
  isUnrestrictedResolver(resolver) and
  dtd = getAValueForDtdProp(settings, end) and
  (
    isDtdParse(dtd)
    or
    dtd.(BoolLiteral).getBoolValue() = false
  )
}

/**
 * Holds if `settings` is insecure with `resolver` when `create` uses it: at `create` itself when
 * both are in the same callable, otherwise where `settings` is returned.
 */
predicate insecureSettingsAt(
  XmlParserConfigCreation settings, XmlReaderCreateCall create, Expr resolver
) {
  exists(ControlFlowElement end | insecureSettings(settings, end, _, resolver) |
    end = create
    or
    end instanceof ReturnStmt and
    create.getEnclosingCallable() != settings.getEnclosingCallable()
  )
}

/** A call to `XmlReader.Create` that reads XML with the given settings. */
class XmlReaderCreateCall extends MethodCall {
  XmlReaderCreateCall() {
    this.getTarget().hasFullyQualifiedName("System.Xml", "XmlReader", "Create") and
    // A wrapped reader keeps the DTD processing of the reader it wraps.
    not this.getArgument(0)
        .getType()
        .(RefType)
        .getABaseType*()
        .hasFullyQualifiedName("System.Xml", "XmlReader")
  }

  /** Gets the `XmlReaderSettings` argument of this call. */
  Expr getSettingsArgument() {
    result = this.getAnArgument() and
    result.getType().(RefType).hasFullyQualifiedName("System.Xml", "XmlReaderSettings")
  }
}

module InsecureSettingsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { insecureSettings(source.asExpr(), _, _, _) }

  predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(XmlReaderCreateCall create).getSettingsArgument()
  }
}

module InsecureSettingsFlow = DataFlow::Global<InsecureSettingsConfig>;

from Call parser, Expr resolver, string kind
where
  exists(XmlParserConfigCreation settings, XmlReaderCreateCall create |
    create = parser and
    insecureSettingsAt(settings, create, resolver) and
    InsecureSettingsFlow::flow(DataFlow::exprNode(settings),
      DataFlow::exprNode(create.getSettingsArgument())) and
    kind = "XmlReaderSettings with DTD processing enabled"
  )
  or
  // `XmlTextReader` processes DTDs by default, so an unrestricted resolver is enough
  // unless DTD processing is explicitly disabled.
  parser.(ObjectCreation).getObjectType().hasFullyQualifiedName("System.Xml", "XmlTextReader") and
  exists(MethodCall read |
    DataFlow::localExprFlow(parser, read.getQualifier()) and
    read.getTarget().getName() in ["Read", "ReadAsync"] and
    resolver = getAValueForProp(parser, "XmlResolver", read) and
    isUnrestrictedResolver(resolver) and
    not isDtdDisabled(getAValueForDtdProp(parser, read)) and
    kind = "XmlTextReader with DTD processing enabled"
  )
select parser, "This XML parser resolves external entities: " + kind + " and an unrestricted $@.",
  resolver, "XmlResolver"
