/**
 * Definitions for reasoning about untrusted data used in APIs defined outside the
 * database.
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

/**
 * A `Method` that is considered a "safe" external API from a security perspective.
 */
abstract class SafeExternalApiMethod extends Method { }

/** The default set of "safe" external APIs. */
private class DefaultSafeExternalApiMethod extends SafeExternalApiMethod {
  DefaultSafeExternalApiMethod() {
    this instanceof EqualsMethod
    or
    this.hasName(["size", "length", "compareTo", "getClass", "lastIndexOf"])
    or
    this.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "Validate")
    or
    this.hasQualifiedName("java.util", "Objects", "equals")
    or
    this.getDeclaringType() instanceof TypeString and this.getName() = "equals"
    or
    this.getDeclaringType().hasQualifiedName("com.google.common.base", "Preconditions")
    or
    this.getDeclaringType().getPackage().getName().matches("org.junit%")
    or
    this.getDeclaringType().hasQualifiedName("com.google.common.base", "Strings") and
    this.getName() = "isNullOrEmpty"
    or
    this.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringUtils") and
    this.getName() = "isNotEmpty"
    or
    this.getDeclaringType().hasQualifiedName("java.lang", "Character") and
    this.getName() = "isDigit"
    or
    this.getDeclaringType().hasQualifiedName("java.lang", "String") and
    this.hasName(["equalsIgnoreCase", "regionMatches"])
    or
    this.getDeclaringType().hasQualifiedName("java.lang", "Boolean") and
    this.getName() = "parseBoolean"
    or
    this.getDeclaringType().hasQualifiedName("org.apache.commons.io", "IOUtils") and
    this.getName() = "closeQuietly"
    or
    this.getDeclaringType().hasQualifiedName("org.springframework.util", "StringUtils") and
    this.hasName(["hasText", "isEmpty"])
    or
    // SECLAB: Exclude all JDK methods
    isJdkInternal(this.getCompilationUnit())
  }
}

/** A node representing data being passed to an external API. */
class ExternalApiDataNode extends DataFlow::Node {
  Call call;
  int i;

  ExternalApiDataNode() {
    (
      // Argument to call to a method
      this.asExpr() = call.getArgument(i)
      or
      // Qualifier to call to a method which returns non trivial value
      this.asExpr() = call.getQualifier() and
      i = -1 and
      not call.getCallee().getReturnType() instanceof VoidType and
      not call.getCallee().getReturnType() instanceof BooleanType
    ) and
    // Defined outside the source archive
    not call.getCallee().fromSource() and
    // Not a call to an method which is overridden in source
    not exists(Method m |
      m.getASourceOverriddenMethod() = call.getCallee().getSourceDeclaration() and
      m.fromSource()
    ) and
    // Not already modeled as a taint step (we need both of these to handle `AdditionalTaintStep` subclasses as well)
    not TaintTracking::localTaintStep(this, _) and
    not TaintTracking::defaultAdditionalTaintStep(this, _, _) and
    // Not a call to a known safe external API
    not call.getCallee() instanceof SafeExternalApiMethod and
    // SECLAB: Not in a test file
    not isInTestFile(call.getLocation().getFile())
  }

  /** Gets the called API `Method`. */
  Method getMethod() { result = call.getCallee() }

  /** Gets the index which is passed untrusted data (where -1 indicates the qualifier). */
  int getIndex() { result = i }

  /** Gets the description of the method being called. */
  string getMethodDescription() { result = this.getMethod().getQualifiedName() }
}

/**
 * DEPRECATED: Use `UntrustedDataToExternalApiFlow` instead.
 *
 * A configuration for tracking flow from `RemoteFlowSource`s to `ExternalApiDataNode`s.
 */
deprecated class UntrustedDataToExternalApiConfig extends TaintTracking::Configuration {
  UntrustedDataToExternalApiConfig() { this = "UntrustedDataToExternalAPIConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof ExternalApiDataNode }
}

/**
 * Taint tracking configuration for flow from `ActiveThreatModelSource`s to `ExternalApiDataNode`s.
 */
module UntrustedDataToExternalApiConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ExternalApiDataNode }
}

/**
 * Tracks flow from untrusted data to external APIs.
 */
module UntrustedDataToExternalApiFlow = TaintTracking::Global<UntrustedDataToExternalApiConfig>;

/** A node representing untrusted data being passed to an external API. */
class UntrustedExternalApiDataNode extends ExternalApiDataNode {
  UntrustedExternalApiDataNode() { UntrustedDataToExternalApiFlow::flowTo(this) }

  /** Gets a source of untrusted data which is passed to this external API data node. */
  DataFlow::Node getAnUntrustedSource() { UntrustedDataToExternalApiFlow::flow(result, this) }
}

/** An external API which is used with untrusted data. */
private newtype TExternalApi =
  /** An untrusted API method `m` where untrusted data is passed at `index`. */
  TExternalApiParameter(Method m, int index) {
    exists(UntrustedExternalApiDataNode n |
      m = n.getMethod() and
      index = n.getIndex()
    )
  }

/** An external API which is used with untrusted data. */
class ExternalApiUsedWithUntrustedData extends TExternalApi {
  /** Gets a possibly untrusted use of this external API. */
  UntrustedExternalApiDataNode getUntrustedDataNode() {
    this = TExternalApiParameter(result.getMethod(), result.getIndex())
  }

  /** Gets the number of untrusted sources used with this external API. */
  int getNumberOfUntrustedSources() {
    result = count(this.getUntrustedDataNode().getAnUntrustedSource())
  }

  /** Gets a textual representation of this element. */
  string toString() {
    exists(Method m, int index, string indexString |
      if index = -1 then indexString = "qualifier" else indexString = "param " + index
    |
      this = TExternalApiParameter(m, index) and
      // SECLAB: use the CSV library to get the 6 first columns
      result = asPartialModel(m) + index.toString()
    )
  }
}

// SECLAB: predicates from https://github.com/github/codeql/blob/main/java/ql/src/utils/modelgenerator/internal/CaptureModelsSpecific.qll
// We cannot import them directly as they are based on TargetApiSpecific which checks for `fromSource()`
private import java as J
private import semmle.code.java.dataflow.ExternalFlow as ExternalFlow
private import semmle.code.java.dataflow.internal.FlowSummaryImpl as FlowSummaryImpl

private predicate isInfrequentlyUsed(J::CompilationUnit cu) {
  cu.getPackage().getName().matches("javax.swing%") or
  cu.getPackage().getName().matches("java.awt%")
}

private predicate relevant(Callable api) {
  api.isPublic() and
  api.getDeclaringType().isPublic() and
  api.fromSource() and
  not isUninterestingForModels(api) and
  not isInfrequentlyUsed(api.getCompilationUnit())
}

private J::Method getARelevantOverride(J::Method m) {
  result = m.getAnOverride() and
  relevant(result) and
  // Other exclusions for overrides.
  not m instanceof J::ToStringMethod
}

/**
 * Gets the super implementation of `m` if it is relevant.
 * If such a super implementations does not exist, returns `m` if it is relevant.
 */
private J::Callable liftedImpl(J::Callable m) {
  (
    result = getARelevantOverride(m)
    or
    result = m and relevant(m)
  ) and
  not exists(getARelevantOverride(result))
}

private predicate hasManualModel(Callable api) {
  api = any(FlowSummaryImpl::Public::SummarizedCallable sc | sc.applyManualModel()).asCallable() or
  api = any(FlowSummaryImpl::Public::NeutralSummaryCallable sc | sc.hasManualModel()).asCallable()
}

/**
 * A class of callables that are potentially relevant for generating summary, source, sink
 * and neutral models.
 *
 * In the Standard library and 3rd party libraries it is the callables (or callables that have a
 * super implementation) that can be called from outside the library itself.
 */
class TargetApiSpecific extends Callable {
  private Callable lift;

  TargetApiSpecific() {
    lift = liftedImpl(this) and
    not hasManualModel(lift)
  }

  /**
   * Gets the callable that a model will be lifted to.
   */
  Callable lift() { result = lift }

  /**
   * Holds if this callable is relevant in terms of generating models.
   */
  predicate isRelevant() { relevant(this) }
}

private string isExtensible(Callable c) {
  if c.getDeclaringType().isFinal() then result = "false" else result = "true"
}

/**
 * Returns the appropriate type name for the model.
 */
private string typeAsModel(Callable c) {
  exists(RefType type | type = c.getDeclaringType() |
    result =
      type.getCompilationUnit().getPackage().getName() + ";" +
        type.getErasure().(J::RefType).getNestedName()
  )
}

private predicate partialModel(
  Callable api, string type, string extensible, string name, string parameters
) {
  type = typeAsModel(api) and
  extensible = isExtensible(api) and
  name = api.getName() and
  parameters = ExternalFlow::paramsString(api)
}

/**
 * Computes the first 6 columns for MaD rows.
 */
string asPartialModel(TargetApiSpecific api) {
  exists(string type, string extensible, string name, string parameters |
    partialModel(api.lift(), type, extensible, name, parameters) and
    result =
      type + ";" //
        + extensible + ";" //
        + name + ";" //
        + parameters + ";" //
        + /* ext + */ ";" //
  )
}

// SECLAB: check if the package is internal to the JDK
// https://github.com/github/codeql/blob/67e2ea195f092347f3d9b5f976c649d6e9fcc219/java/ql/lib/semmle/code/java/dataflow/internal/ModelExclusions.qll#L77
/** Holds if the given package `p` is a test package. */
pragma[nomagic]
private predicate isTestPackage(Package p) {
  p.getName()
      .matches([
          "org.junit%", "junit.%", "org.mockito%", "org.assertj%",
          "com.github.tomakehurst.wiremock%", "org.hamcrest%", "org.springframework.test.%",
          "org.springframework.mock.%", "org.springframework.boot.test.%", "reactor.test%",
          "org.xmlunit%", "org.testcontainers.%", "org.opentest4j%", "org.mockserver%",
          "org.powermock%", "org.skyscreamer.jsonassert%", "org.rnorth.visibleassertions",
          "org.openqa.selenium%", "com.gargoylesoftware.htmlunit%", "org.jboss.arquillian.testng%",
          "org.testng%"
        ])
}

/**
 * A test library.
 */
class TestLibrary extends RefType {
  TestLibrary() { isTestPackage(this.getPackage()) }
}

/** Holds if the given compilation unit's package is internal. */
private predicate isInternal(CompilationUnit cu) {
  isJdkInternal(cu) or
  cu.getPackage().getName().matches("%internal%")
}

/** A method relating to lambda flow. */
private class LambdaFlowMethod extends Method {
  LambdaFlowMethod() {
    this.hasQualifiedName("java.lang", "Runnable", "run") or
    this.hasQualifiedName("java.util", "Comparator",
      ["comparing", "comparingDouble", "comparingInt", "comparingLong"]) or
    this.hasQualifiedName("java.util.function", "BiConsumer", "accept") or
    this.hasQualifiedName("java.util.function", "BiFunction", "apply") or
    this.hasQualifiedName("java.util.function", "Consumer", "accept") or
    this.hasQualifiedName("java.util.function", "Function", "apply") or
    this.hasQualifiedName("java.util.function", "Supplier", "get")
  }
}

/** Holds if the given callable is not worth modeling. */
predicate isUninterestingForModels(Callable c) {
  isInTestFile(c.getCompilationUnit().getFile()) or
  isInternal(c.getCompilationUnit()) or
  c instanceof MainMethod or
  c instanceof ToStringMethod or
  c instanceof LambdaFlowMethod or
  c instanceof StaticInitializer or
  exists(FunctionalExpr funcExpr | c = funcExpr.asMethod()) or
  c.getDeclaringType() instanceof TestLibrary or
  c.(Constructor).isParameterless()
}

/** Holds if the given file is a test file. */
predicate isInTestFile(File file) {
  file.getAbsolutePath().matches(["%/test/%", "%/guava-tests/%", "%/guava-testlib/%"]) and
  not file.getAbsolutePath().matches(["%/ql/test/%", "%/ql/automodel/test/%"]) // allows our test cases to work
}

/** Holds if the given compilation unit's package is a JDK internal. */
private predicate isJdkInternal(CompilationUnit cu) {
  cu.getPackage().getName().matches("org.graalvm%") or
  cu.getPackage().getName().matches("com.sun%") or
  cu.getPackage().getName().matches("sun%") or
  cu.getPackage().getName().matches("jdk%") or
  cu.getPackage().getName().matches("java2d%") or
  cu.getPackage().getName().matches("build.tools%") or
  cu.getPackage().getName().matches("propertiesparser%") or
  cu.getPackage().getName().matches("org.jcp%") or
  cu.getPackage().getName().matches("org.w3c%") or
  cu.getPackage().getName().matches("org.ietf.jgss%") or
  cu.getPackage().getName().matches("org.xml.sax%") or
  cu.getPackage().getName().matches("com.oracle%") or
  cu.getPackage().getName().matches("org.omg%") or
  cu.getPackage().getName().matches("org.relaxng%") or
  cu.getPackage().getName() = "compileproperties" or
  cu.getPackage().getName() = "transparentruler" or
  cu.getPackage().getName() = "genstubs" or
  cu.getPackage().getName() = "netscape.javascript" or
  cu.getPackage().getName() = "" or
  // SECLAB add java package
  cu.getPackage().getName().matches("java.%") or
  cu.getPackage().getName().matches("javax.%")
}
