import ql

private File imports(File importer) {
  // returns all files imported from `importer`
  exists(Import imp |
    imp.getLocation().getFile() = importer and
    result = imp.getResolvedModule().getFile()
  )
}

private string getFileImport(Container f) {
  f = f.getParentContainer*() and
  (
    if exists(f.(Folder).getFile("qlpack.yml"))
    then result = ""
    else
      result =
        getFileImport(f.getParentContainer()) + "." + f.getBaseName().regexpReplaceAll("\\..*", "")
  )
}

private string getAbsoluteImportString(Import i) {
  result = getFileImport(i.getResolvedModule().getFile()).suffix(1)
}

/**
 * A Taint tracking configuration. Either a Class or a Module.
 */
abstract class TaintTrackingConfiguration extends ModuleDeclaration {
  /**
   * Returns true if the taint trackin configuration is a state configuration.
   */
  abstract string isStateConfig();

  /**
   * Returns the kind of this configuration.
   *  - "class" for a class configuration
   *  - "module" for a module configuration
   */
  abstract string getKind();

  /**
   * Returns the fully qualified name of this configuration.
   */
  abstract string getQualifiedName();

  /**
   * Returns the name of the language this configuration is for.
   */
  string getLanguage() { result = this.getLocation().getFile().getRelativePath().splitAt("/", 0) }

  /**
   * Returns the name of the language this configuration is for.
   */
  string getPath() { result = this.getLocation().getFile().getRelativePath() }

  /**
   * Returns the isSink predicate of this configuration.
   */
  abstract Predicate getIsSinkPredicate();

  /**
   * Returns the isSource predicate of this configuration.
   */
  abstract Predicate getIsSourcePredicate();

  /**
   * Returns the name of the QL pack this configuration is in.
   */
  string getQLPack() {
    if this.getLocation().getFile().getRelativePath().matches(this.getLanguage() + "/ql/lib/%")
    then result = "codeql/" + this.getLanguage() + "-all"
    else
      if this.getLocation().getFile().getRelativePath().matches(this.getLanguage() + "/ql/src/%")
      then result = "codeql/" + this.getLanguage() + "-queries"
      else
        if
          this.getLocation()
              .getFile()
              .getRelativePath()
              .matches(this.getLanguage() + "/ql/experimental/%")
        then result = "codeql/" + this.getLanguage() + "-experimental"
        else result = "unknown"
  }

  /**
   * Returns the import string necessary to import this configuration.
   */
  string getImportStringFrom(File root) {
    exists(TopLevel tl | tl.getLocation().getFile() = root |
      (
        if this.getLocation().getFile() = root
        then result = getFileImport(root).suffix(1)
        else
          exists(Import i |
            i = tl.getAnImport() and
            this.getLocation()
                .getFile()
                .getRelativePath()
                .splitAt(".", 0)
                .replaceAll("/", ".")
                .suffix(1)
                .matches("%" + i.getImportString()) and
            result = getAbsoluteImportString(i)
          )
      )
    )
  }
}

/**
 * A DataFlow/TaintTracking configuration class
 */
class TaintTrackingConfigClass extends TaintTrackingConfiguration instanceof Class {
  string stateConfig;
  Predicate isSink;
  Predicate isSource;

  TaintTrackingConfigClass() {
    not this.hasAnnotation("deprecated") and
    exists(TypeExpr taint, Type conf |
      this.getASuperType() = taint and
      // Get parent classes since CSharp TTCs extends from TaintTrackingConfiguration which
      // extends from TaintTracking2::Configuration
      taint.getResolvedType().getASuperType*() = conf and
      conf.getName() = "Configuration" and
      exists(Predicate supIsSink, Predicate supIsSource |
        supIsSink = conf.getClassPredicate("isSink", _) and
        supIsSource = conf.getClassPredicate("isSource", _)
      ) and
      this.getMember(_) = isSource and
      isSource.getName() = "isSource" and
      this.getMember(_) = isSink and
      isSink.getName() = "isSink" and
      (
        isSink.getArity() > 1 and stateConfig = "true"
        or
        isSink.getArity() = 1 and stateConfig = "false"
      ) and
      // exclude python's old TaintTracking::Sink
      not exists(Predicate pred |
        this.getAClassPredicate() = pred and
        pred.getName() = "isSink" and
        pred.getParameterType(0).getName() = "TaintSink"
      ) and
      // Ignore the `TaintTracking::Configuration` and `DataFlow::Configuration` class themselves
      not this.(Class)
          .getLocation()
          .getFile()
          .getBaseName()
          .matches(["DataFlow", "TaintTracking"] + "%.qll") and
      // Ignore JS ATM queries
      not this.(Class)
          .getLocation()
          .getFile()
          .getRelativePath()
          .matches("javascript/ql/experimental/%")
    )
  }

  override Predicate getIsSinkPredicate() { result = isSink }

  override Predicate getIsSourcePredicate() { result = isSource }

  private predicate belongsTo(Module m) {
    m.getLocation().getFile() = this.getLocation().getFile() and
    m.getAMember() = this
  }

  private string getModulePrefix() {
    // follow formula: `exists(T t | p(t) | res1(t)) or not exists(T t | p(t)) and res2()`
    exists(Module m | this.belongsTo(m) | result = m.getName() + "::")
    or
    not exists(Module m | this.belongsTo(m)) and result = ""
  }

  override string getQualifiedName() { result = this.getModulePrefix() + this.getName() }

  override string getKind() { result = "class" }

  override string isStateConfig() { result = stateConfig }
}

/**
 * A module implementing the DataFlow::ConfigSig signature
 */
class DataFlowConfigModule extends Module {
  DataFlowConfigModule() {
    exists(Module sig |
      this.getImplements(_).getResolvedModule().asModule() = sig and
      sig.getName() = ["ConfigSig", "StateConfigSig"] and
      sig.getFile().getBaseName().matches("%DataFlow.qll") and
      sig.isSignature()
    )
  }
}

/**
 * A DataFlow ConfigSig implementing module that is used as a parameter for `TaintTracking::Global`
 */
class TaintTrackingConfigModule extends TaintTrackingConfiguration instanceof Module {
  DataFlowConfigModule config;
  string stateConfig;
  Predicate isSink;
  Predicate isSource;

  TaintTrackingConfigModule() {
    not this.hasAnnotation("deprecated") and
    exists(ModuleExpr global |
      global.getQualifier().getName() = ["DataFlow", "TaintTracking"] and
      global.getName() = ["Global", "GlobalWithState"] and
      global.getArgument(0).(SignatureExpr).asType().getResolvedModule().asModule() = config and
      config.getAMember() = isSink and
      isSink.getName() = "isSink" and
      config.getAMember() = isSource and
      isSource.getName() = "isSource" and
      (
        exists(VarDecl p | p = isSink.getParameter(1) and stateConfig = "true")
        or
        not exists(VarDecl p | p = isSink.getParameter(1)) and stateConfig = "false"
      ) and
      this.getAlias() = global and
      not this.(Module)
          .getLocation()
          .getFile()
          .getRelativePath()
          .matches(["%/ql/test/%", "%/DataFlow.qll", "%/DefaultTaintTrackingImpl.qll"])
    )
  }

  override Predicate getIsSinkPredicate() { result = isSink }

  override Predicate getIsSourcePredicate() { result = isSource }

  DataFlowConfigModule getConfigModule() { result = config }

  override string getQualifiedName() {
    exists(Module p | p.getAMember() = config | result = p.getName() + "::" + config.getName())
    or
    not exists(Module p | p.getAMember() = config) and result = config.getName()
  }

  override string getKind() { result = "module" }

  override string isStateConfig() { result = stateConfig }
}

/**
 * A Security-related path-problem query
 */
class SecurityQuery extends File {
  SecurityQuery() {
    this.getExtension() = "ql" and
    not this.getRelativePath().matches("%/test/%") and
    exists(QLDoc doc | doc.getLocation().getFile() = this |
      doc.getContents().matches("%@kind path-problem%") and
      doc.getContents().matches("% security%") and
      doc.getContents().matches("%/cwe/%")
    ) and
    not exists(Predicate e |
      e.getName() = "edges" and
      e.getLocation().getFile() = this
    )
  }

  string getPath() { result = this.getRelativePath() }

  string getMetadata() {
    exists(QLDoc doc | doc.getLocation().getFile() = this |
      doc.getContents().matches("%@kind %") and
      doc.getContents().matches("%@id %") and
      result = doc.getContents()
    )
  }

  string getId() {
    result = any(string s | s = this.getMetadata().splitAt("\n") | s.regexpCapture(".*@id (.*)", 1))
  }

  float getSeverity() {
    exists(string s | s = this.getMetadata().splitAt("\n") |
      result = s.regexpCapture(".*@security-severity (.*)", 1).toFloat()
    )
    or
    not exists(string s | s = this.getMetadata().splitAt("\n") |
      s.regexpMatch(".*@security-severity (.*)")
    ) and
    result = -1.0
  }

  string getLanguage() { result = this.getRelativePath().splitAt("/", 0) }
}

/**
 * A Security query with an identified TaintTracking configuration
 */
class TaintTrackingSecurityQuery extends SecurityQuery {
  TaintTrackingConfiguration ttconfig;

  TaintTrackingSecurityQuery() {
    (
      // the taint tracking config class/module is defined in a file that is imported from this file
      ttconfig.getLocation().getFile() = imports*(this)
      or
      // the taint tracking config class/module is defined in the same file as the query
      ttconfig.getLocation().getFile() = this
    ) and
    (
      ttconfig instanceof TaintTrackingConfigClass and
      exists(TypeExpr ttcExpr, Select selectClause |
        selectClause = any(Select s | s.getLocation().getFile() = this) and
        ttcExpr.getResolvedType() = ttconfig.(Class).getType().getASuperType*() and
        //ttcExpr.getResolvedType().getASuperType*().getName() = "Configuration" and
        not ttcExpr.getResolvedType().getName() = "string" and
        (
          // TTC is declared in the FROM clause: `from Config config, ...`
          // TTC is defined in the WHERE clause: `where any(Config c | ...)`
          selectClause.getAChild*() = ttcExpr
          or
          // TTC is defined in a nested predicate: `where queryTaintedBy(query, source, sink)`
          exists(PredicateCall call |
            call.getParent*() = selectClause and
            call.getTarget() = ttcExpr.getEnclosingPredicate*()
          )
        )
      )
      or
      ttconfig instanceof TaintTrackingConfigModule and
      (
        exists(Select selectClause |
          selectClause = any(Select s | s.getLocation().getFile() = this) and
          selectClause.getVarDecl(_).getTypeExpr().getModule().getResolvedModule().asModule() =
            ttconfig.(Module)
        )
        or
        exists(Module merged, ModuleExpr me |
          merged.getAlias() = me and
          me.getQualifier().getName() = ["DataFlow", "TaintTracking"] and
          me.getName().matches("MergePathGraph%") and
          me.getArgument(_).(TypeExpr).getModule().getResolvedModule().asModule() =
            ttconfig.(Module)
        )
      )
    )
  }

  TaintTrackingConfiguration getTaintTrackingConfiguration() { result = ttconfig }
}
