private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.pointsto.CallGraph

class User extends ClassDef {
  Class class_;
  string name;
  Expr base;
  Value ref;
  string password_variable;

  User() {
    this.getDefinedClass() = class_ and
    class_.getName() = name and
    class_.getABase() = base and
    base.pointsTo(ref) and
    (
      ref.getName() = "UserMixin" and
      password_variable = "password"
      or
      ref.getName() = "Model" and
      exists(class_.getInitMethod().getArgByName(password_variable)) and
      password_variable.regexpMatch("^(?:password|pass|pwd|passwd)$")
    )
  }

  predicate usesUserMixin() { ref.getName() = "UserMixin" }

  string getPasswordVariable() { result = password_variable }

  string getName() { result = name }

  Function getInit() { result = class_.getInitMethod() }

  predicate hasInit() { exists(class_.getInitMethod()) }

  predicate inInit(DataFlow::Node node) { this.getInit().getBody().contains(node.asExpr()) }

  // TODO: account for named arguments? Can that we used for this?
  predicate isPasswordArg(DataFlow::Node node) {
    exists(Variable var |
      node.asExpr() = this.getInit().getArg(2) and
      node.asExpr() = var.getAnAccess()
    )
  }

  predicate passwordAssignedFrom(DataFlow::Node node) {
    this.inInit(node) and
    exists(SelfPasswordAttribute password |
      this.inInit(password) and
      password.assignedFrom(node)
    )
  }

  predicate hasSecureInit() {
    this.hasInit() and
    not exists(InsecureHashTrackingConfiguration conf, DataFlow::Node source, DataFlow::Node sink |
      this.inInit(sink) and
      this.isPasswordArg(source) and
      conf.hasFlow(source, sink)
    )
  }

  predicate usedSecurely() {
    not exists(InsecureTaintTrackingConfiguration conf, DataFlow::Node source, DataFlow::Node sink |
      conf.hasFlow(source, sink) and
      sink.(PasswordArg).getUser() = this
    )
  }

  predicate isSecure() {
    this.hasSecureInit()
    or
    not this.hasSecureInit() and this.usedSecurely()
  }
}

class InsecureTaintTrackingConfiguration extends TaintTracking::Configuration {
  // is the password used in the init of the User protected by a secure hash?
  InsecureTaintTrackingConfiguration() { this = "InsecureTaintTrackingConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof PasswordArg }

  override predicate isAdditionalTaintStep(DataFlow::Node a, DataFlow::Node b) {
    // from a dict key to the dict, if the key is "password"
    exists(Dict dict, KeyValuePair pair |
      dict.getAnItem() = pair and
      pair.getKey().toString().regexpMatch("^(?:password|pass|pwd|passwd)$") and
      a.asExpr() = pair.getValue() and
      b.asExpr() = dict
    )
  }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof HashSanitizer }
}

class InsecureHashTrackingConfiguration extends TaintTracking::Configuration {
  User user;

  // does the body of the init of the User hash the password?
  InsecureHashTrackingConfiguration() { this = "InsecureHashTrackingConfiguration" }

  override predicate isSource(DataFlow::Node source) { user.isPasswordArg(source) }

  override predicate isSink(DataFlow::Node sink) {
    user.passwordAssignedFrom(sink) and
    not sink instanceof HashSanitizer
  }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof HashSanitizer }
}

// assigment to self.password
class SelfPasswordAttribute extends DataFlow::Node {
  Variable self;
  Name self_access;
  Attribute password;
  string password_attr_name;

  SelfPasswordAttribute() {
    this.asExpr() = password and
    password_attr_name.regexpMatch("^(?:password|pass|pwd|passwd)$") and
    password.getObject(password_attr_name) = self_access and
    self.isSelf() and
    self_access = self.getAnAccess()
  }

  predicate assignedFrom(DataFlow::Node node) {
    exists(AssignStmt assign |
      assign.getValue().getAChildNode*() = node.asExpr() and
      assign.getATarget() = this.asExpr()
    )
  }
}

class PasswordArg extends DataFlow::Node {
  User user;
  Call init;

  PasswordArg() {
    // it's an init of User
    init.getFunc().(Name).getId() = user.getName() and
    (
      // positional arg 1
      init.getPositionalArg(1) = this.asExpr()
      or
      // named arg "password"
      exists(int i, string name |
        init.getArg(i) = this.asExpr() and
        init.getANamedArgumentName() = name and
        init.getNamedArg(i).(KeyValuePair).getKey().toString() = name and
        name = user.getPasswordVariable()
      )
      or
      // **kwargs
      init.getKwargs() = this.asExpr() and
      not exists(init.getPositionalArg(1)) and
      not exists(string name |
        init.getANamedArgumentName() = name and
        init.getANamedArg().(KeyValuePair).getKey().toString() = name and
        name = user.getPasswordVariable()
      )
    )
  }

  Call getInit() { result = init }

  User getUser() { result = user }
}

abstract class HashSanitizer extends DataFlow::Node {
  HashSanitizer() { this = this }
}

class HashSanitizerConcrete extends HashSanitizer {
  HashSanitizerConcrete() {
    exists(API::Node member |
      API::moduleImport("flask_security").getMember("hash_password") = member
      or
      API::moduleImport("flask_security").getMember("utils").getMember("hash_password") = member
      or
      API::moduleImport("werkzeug").getMember("security").getMember("generate_password_hash") =
        member
      or
      API::moduleImport("werkzeug").getMember("generate_password_hash") = member
      or
      API::moduleImport("flask_bcrypt").getMember("Bcrypt").getMember("generate_password_hash") =
        member
      or
      API::moduleImport("flask_argon2").getMember("Argon2").getMember("generate_password_hash") =
        member
    |
      this = member.getACall().getParameter(0, ["password", "pass", "pwd", "passwd"]).asSink()
    )
  }
}

private import semmle.python.dataflow.new.internal.DataFlowDispatch as DataFlowDispatch

/** Holds if the `call` is a call to the function `target`. */
private predicate resolveCall(CallNode call, Function target) {
    // TODO: This should be exposed better from the standard library API
    DataFlowDispatch::resolveCall(call, target, _)
}

/**
 * From real world cases, we see that if the password is hashed in a wrapper function,
 * the data-flow library fails to break the flow. To handle that, we assume that first
 * argument to any function that performs strong password hashing in its' body, can also
 * be considered a sanitizer.
 *
 * We are keeping it very simple. If we run into FPs or FNs we can make it more complex.
 */
class HashSanitizerWrapperFunction extends HashSanitizer {
  HashSanitizerWrapperFunction() {
    exists(CallNode hashCall, Function hashWrapper |
        hashWrapper.contains(any(HashSanitizerConcrete hsc).asExpr()) and
        resolveCall(hashCall, hashWrapper) and
        this.asCfgNode() = hashCall.getArg(0)
    )
  }
}
