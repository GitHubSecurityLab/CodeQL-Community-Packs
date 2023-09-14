import semmle.code.SMAP

class JSPExpr extends string {
  Expr javaExpr;

  JSPExpr() {
    exists(string jspPath, int jspStartLine, int jspStartChar, int jspEndLine |
      hasSmapLocationInfo(jspPath, jspStartLine, jspStartChar, jspEndLine, _,
        javaExpr.getLocation().getFile().getAbsolutePath(), javaExpr.getLocation().getStartLine(),
        javaExpr.getLocation().getEndLine()) and
      this =
        "file://" + jspPath + ":" + jspStartLine + ":" + jspStartChar + ":" + jspEndLine + ":" + 1
    )
  }

  string getURL() { result = this }

  Expr getJavaExpr() { result = javaExpr }

  predicate isClosest(Expr expr) { this = getClosestJSPExpr(expr) }
}

private int nestingDepth(Expr parent, Expr child) {
  if child = parent then result = 0 else result = nestingDepth(parent, child.getParent()) + 1
}

private JSPExpr getClosestJSPExpr(Expr javaExpr) {
  exists(
    min(Expr parent |
      result.getJavaExpr() = parent and parent = javaExpr.getParent*()
    |
      nestingDepth(parent, javaExpr)
    )
  )
}
