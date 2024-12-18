private import python

// password = db.Column(..., server_default=...)
class DBColumn extends Call {
  CallNode call;
  string name;
  ControlFlowNode object;
  Name var;
  string id;

  DBColumn() {
    call.getFunction().(AttrNode).getObject(name) = object and
    name = "Column" and
    call = this.getAFlowNode() and
    object.getNode() = var.getVariable().getAnAccess() and
    var.getId() = id
  }

  string getDbId() { result = id }

  predicate hasStaticDefault() {
    exists(DictItem arg |
      arg = call.getNode().getANamedArg() and
      arg.(Keyword).getArg() in ["server_default", "default"] and
      arg.(Keyword).getValue() instanceof ImmutableLiteral
    )
  }

  string assignedToVariable() {
    exists(AssignStmt assign, Variable v |
      assign.defines(v) and
      v.getId() = result and
      assign.getValue() = this
    )
  }

  string getColumnName() { result = call.getNode().getArg(0).(StringLiteral).getText() }
}
