private import csharp
private import semmle.code.csharp.frameworks.Moq
private import semmle.code.csharp.frameworks.System
private import semmle.code.csharp.dataflow.TaintTracking

/**
 * A data flow source for hard coded credentials.
 */
abstract class Source extends DataFlow::ExprNode { }

/**
 * A data flow sink for hard coded credentials.
 */
abstract class Sink extends DataFlow::ExprNode { }

/**
 * A sanitizer for hard coded credentials.
 */
abstract class Sanitizer extends DataFlow::ExprNode { }

/**
 * A string literal that is not empty, and not an expression placeholder.
 */
class NonEmptyStringLiteral extends Source {
  NonEmptyStringLiteral() {
    exists(StringLiteral literal |
      this.getExpr() = literal and
      literal.getValue().length() > 1 and
      literal.fromSource() and
      not literal.getValue().matches("${%}")
    )
  }
}

/**
 * The creation of a literal byte array.
 */
class ByteArrayLiteral extends Source {
  ByteArrayLiteral() {
    this.getExpr() =
      any(ArrayCreation ac |
        ac.getArrayType().getElementType() instanceof ByteType and
        ac.hasInitializer()
      ) and
    this.getExpr().fromSource()
  }
}

/**
 * The creation of a literal char array.
 */
class CharArrayLiteral extends Source {
  CharArrayLiteral() {
    this.getExpr() =
      any(ArrayCreation ac |
        ac.getArrayType().getElementType() instanceof CharType and
        ac.hasInitializer()
      ) and
    this.getExpr().fromSource()
  }
}

// taint from a string literal to the constructor of a SymmetricSecurityKey
class LiteralToSecurityKeyConfig extends TaintTracking::Configuration {
  LiteralToSecurityKeyConfig() { this = "LiteralToSecurityKeyConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
}

class SymmetricSecurityKey extends Sink {
  SymmetricSecurityKey() {
    exists(ObjectCreation securityKey |
      securityKey.getAnArgument() = this.getExpr() and
      securityKey
          .getType()
          .hasFullyQualifiedName(["Microsoft.IdentityModel.Tokens", "System.IdentityModel.Tokens"],
            "SymmetricSecurityKey")
    )
  }
}

/**
 *  A result from a mock interface
 *  Ignore values that are ultimately returned by mocks, as they don't represent "real" credentials.
 */
class MockSanitizer extends Sanitizer {
  MockSanitizer() {
    exists(ReturnedByMockObject mock |
      mock.getAMemberInitializationValue() = this.asExpr() or
      mock.getAnArgument() = this.asExpr()
    )
  }
}

/**
 *  A result from a mock interface
 *  The function is not itself marked as a mock, but all uses of it are in mocks.
 */
class MockSanitizer2 extends Sanitizer {
  MockSanitizer2() {
    exists(Method method, ReturnedByMockObject mock |
      exists(Call call |
        call = method.getACall() and
        method.getAChild*() = this.asExpr() and
        (
          mock.getAMemberInitializationValue().getAChild*() = call or
          mock.getAnArgument().getAChild*() = call
        )
      ) and
      not exists(Call call |
        call = method.getACall() and
        method.getAChild*() = this.asExpr() and
        not (
          mock.getAMemberInitializationValue().getAChild*() = call or
          mock.getAnArgument().getAChild*() = call
        )
      )
    )
  }
}

/**
 * A format argument to `Format`, that is considered not to be a source of hardcoded secret data.
 */
class StringFormatSanitizer extends Sanitizer {
  StringFormatSanitizer() {
    this.getExpr() =
      any(SystemStringClass s).getFormatMethod().getACall().getArgumentForName("format")
  }
}

/**
 * A replacement argument to `Replace`, that is considered not to be a source of hardcoded secret
 * data.
 */
class StringReplaceSanitizer extends Sanitizer {
  StringReplaceSanitizer() {
    exists(SystemStringClass s, Call c | c = s.getReplaceMethod().getACall() |
      this.getExpr() = c.getArgumentForName("newValue") or
      this.getExpr() = c.getArgumentForName("newChar")
    )
  }
}

/**
 * A call to a `ToString()` method, which is considered not to return hard-coded constants.
 */
class ToStringSanitizer extends Sanitizer {
  ToStringSanitizer() { this.getExpr() = any(Call c | c.getTarget().hasName("ToString")) }
}

/**
 * A call to a configuration section or access to configuration data, using the string as a key.
 */
class ConfigurationSanitizer extends Sanitizer {
  ConfigurationSanitizer() {
    exists(Access configuration, MethodCall call |
      configuration
          .getType()
          .hasFullyQualifiedName("Microsoft.Extensions.Configuration",
            ["IConfiguration", "ConfigurationManager"]) and
      call.getQualifier() = configuration and
      call.getAnArgument() = this.getExpr()
    )
  }
}

/**
 * A call to a file operation, opening or reading from a named file.
 */
class FileSanitizer extends Sanitizer {
  FileSanitizer() {
    exists(Call c |
      c.getTarget()
          .hasFullyQualifiedName("System.IO.File",
            [
              "ReadAllBytes", "ReadAllText", "Open", "OpenText", "OpenRead", "OpenHandle",
              "ReadAllTextAsync", "ReadAllBytesAsync", "ReadAllLines", "ReadAllLinesAsync",
              "ReadLines", "ReadLinesAsync", "OpenTextAsync"
            ]) and
      c.getAnArgument() = this.getExpr()
    )
  }
}

/**
 * An expr within a method of a Class with a TestClass or Fact attribute, or a name that suggests testing
 */
class TestClassSanitizer extends Sanitizer {
  TestClassSanitizer() {
    exists(Class c |
      (
        c.getAnAttribute().getType().getName() = ["TestClassAttribute", "FactAttribute"] or
        c.getName().matches(["Test%", "%Test", "%Tests", "Mock%", "%Mocks", "%Mock", "Fake%"])
      ) and
      (
        this.getExpr() = c.getAMethod().getAChild*() or
        this.getExpr() = c.getAField().getAChild*() or
        this.getExpr() = c.getAProperty().getGetter().getBody().getAChild*()
      )
    )
  }
}

/**
 * An expr within a method of a Class with inside a Namespace that suggests testing
 */
class TestNamespaceSanitizer extends Sanitizer {
  TestNamespaceSanitizer() {
    exists(Namespace n |
      n.getName().matches(["Test%", "%Test", "%Tests", "Mock%", "%Mocks", "%Mock", "Fake%"]) and
      (
        this.getExpr() = n.getAClass().getAMethod().getAChild*() or
        this.getExpr() = n.getAClass().getAField().getAChild*() or
        this.getExpr() = n.getAClass().getAProperty().getGetter().getBody().getAChild*()
      )
    )
  }
}

/**
 * A preprocessor directive for DEBUG, so this isn't a real secret used in a Release build.
 */
class DebugSanitizer extends Sanitizer {
  DebugSanitizer() {
    exists(
      IfDirective if_d, EndifDirective endif_d, Location if_loc, Location endif_loc, Location loc
    |
      loc = this.getLocation() and
      if_d.getCondition().toString() = "DEBUG" and
      if_d.getEndifDirective() = endif_d and
      if_d.getLocation() = if_loc and
      endif_d.getLocation() = endif_loc and
      loc.getStartLine() > if_loc.getEndLine() and
      loc.getEndLine() < endif_loc.getStartLine() and
      loc.getFile() = if_loc.getFile()
    )
  }
}

