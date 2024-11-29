GETSINKEXPR_DEFAULT = "Expr getSinkExpr(DataFlow::Node n) { result = n.asExpr() }"

GETSINKEXPR_PYTHON = """
Expr getSinkExpr(DataFlow::Node n) { result = n.asExpr() and not n.asExpr() instanceof StrConst }
"""

GETSINKEXPR_JAVA = """
Expr getSinkExpr(DataFlow::Node n) {
  not n.getLocation().getFile().getRelativePath().matches("%/src/test/%") and
  not n.asExpr() instanceof StringLiteral and
  (
      exists(MethodCall ma | ma.getAnArgument() = n.asExpr() and result = ma)
      or
      exists(MethodCall ma | ma.getQualifier() = n.asExpr() and result = ma)
      or
      not exists(MethodCall ma | ma.getAnArgument() = n.asExpr()) and
      result = n.asExpr()
  )
}
"""

GETSINKEXPR_RUBY = """
DataFlow::ExprNode getSinkExpr(DataFlow::Node n) {
  result = n and
  not n.getLocation().getFile().getRelativePath().regexpMatch("(^|.*/)test/.*|(^|.*/)spec/.*|^\\.rubocop/.*|^Gemfile$|.*/extconf.rb$|.*/setup.rb$")
}
"""

LOCATIONPRED_DEFAULT = """
string getPath(DataFlow::Node n) { result = n.getLocation().getFile().getRelativePath() }

int getStartLine(DataFlow::Node n) { result = n.getLocation().getStartLine() }

int getEndLine(DataFlow::Node n) { result = n.getLocation().getEndLine() }

int getStartColumn(DataFlow::Node n) { result = n.getLocation().getStartColumn() }

int getEndColumn(DataFlow::Node n) { result = n.getLocation().getEndColumn() }
"""

LOCATIONPRED_JAVASCRIPT = """
string getPath(DataFlow::Node n) { result = n.getFile().getRelativePath() }

int getStartLine(DataFlow::Node n) { result = n.getStartLine() }

int getEndLine(DataFlow::Node n) { result = n.getEndLine() }

int getStartColumn(DataFlow::Node n) { result = n.getStartColumn() }

int getEndColumn(DataFlow::Node n) { result = n.getEndColumn() }
"""

LOCATIONPRED_GO = """
string getPath(DataFlow::Node n) { result = n.getFile().getRelativePath() }

int getStartLine(DataFlow::Node n) { result = n.getStartLine() }

int getEndLine(DataFlow::Node n) { result = n.getEndLine() }

int getStartColumn(DataFlow::Node n) { result = n.getStartColumn() }

int getEndColumn(DataFlow::Node n) { result = n.getEndColumn() }
"""

CONFIG_CLASS_CHECK_TEMPLATE = '  exists({namespace}::{config_decl} c | c.isSink(n{state_param}) and type = "{query_id}")'

CONFIG_MODULE_CHECK_TEMPLATE = (
    '  {namespace}::{config_decl}::isSink(n{state_param}) and type = "{query_id}"'
)

QUERY_TEMPLATE = """/**
 * @name Hotspots
 * @description Interesting places to review manually
 * @kind problem
 * @precision low
 * @severity info
 * @id githubsecuritylab/{lang}-hotspots
 * @tags audit
 */

import {lang}
{getImportDataFlow}
{importStatements}

{getSinkExpr}
{locationPredicates}

from DataFlow::Node n, string type
where
{configChecks}
select getSinkExpr(n),
  type + " @ " + getPath(n).toString() + ":" + getStartLine(n).toString() + "," +
    getEndLine(n).toString() + "," + getStartColumn(n).toString() + "," + getEndColumn(n)
"""

sinkExprMap = {
    "java": GETSINKEXPR_JAVA,
    "ruby": GETSINKEXPR_RUBY,
    "python": GETSINKEXPR_PYTHON,
    "cpp": GETSINKEXPR_DEFAULT,
    "csharp": GETSINKEXPR_DEFAULT,
    "javascript": GETSINKEXPR_DEFAULT,
    "go": GETSINKEXPR_DEFAULT,
}

locationPredicateMap = {
    "java": LOCATIONPRED_DEFAULT,
    "ruby": LOCATIONPRED_DEFAULT,
    "python": LOCATIONPRED_DEFAULT,
    "cpp": LOCATIONPRED_DEFAULT,
    "csharp": LOCATIONPRED_DEFAULT,
    "javascript": LOCATIONPRED_JAVASCRIPT,
    "go": LOCATIONPRED_GO,
}

dataflowModuleMap = {
    "java": "import semmle.code.java.dataflow.DataFlow",
    "ruby": "import codeql.ruby.DataFlow",
    "python": "import semmle.python.dataflow.new.DataFlow",
    "cpp": "import semmle.code.cpp.ir.dataflow.DataFlow",
    "csharp": "import semmle.code.csharp.dataflow.DataFlow",
    "javascript": "",
    "go": "",
}

