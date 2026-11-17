/**
 * @name Encoded secret written to workflow log
 * @description The runner masks a secret in the workflow log, and also its Base64, JSON, URL and XML
 *              encodings. Printing the secret after another transformation, for example `xxd`,
 *              `base32` or `rev`, or after a Base64 encoding that changes the masked text, for
 *              example the trailing newline added by `echo` or the line wrapping of long values,
 *              can leave all or part of the secret readable in the log.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id githubsecuritylab/actions/encoded-secret-in-log
 * @tags actions
 *       security
 *       experimental
 *       external/cwe/cwe-532
 */

import actions

/** Holds if `expr` is an Actions expression that evaluates to a secret value. */
bindingset[expr]
predicate isSecretExpression(string expr) {
  exists(string expressionWithoutLiterals |
    expressionWithoutLiterals =
      expr.regexpReplaceAll("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'", "") and
    expressionWithoutLiterals
        .regexpMatch("(?s).*(^|[^A-Za-z0-9_.])(secrets(\\s*\\.\\s*[A-Za-z_][A-Za-z0-9_]*|\\s*\\[[^]]+\\])?|github\\s*\\.\\s*token)([^A-Za-z0-9_]|$).*") and
    not expressionWithoutLiterals.regexpMatch("(?s).*(==|!=|<=|>=|<|>|&&).*") and
    not expressionWithoutLiterals.regexpMatch("(?s)^\\s*!.*") and
    not expressionWithoutLiterals.regexpMatch("(?s).*\\b(contains|startsWith|endsWith)\\s*\\(.*")
  )
}

/** Holds if `offset` points to a shell pipeline separator in `stmt`. */
bindingset[stmt]
private predicate isPipelineSeparator(string stmt, int offset) {
  exists(string pipe | pipe = stmt.regexpFind("\\|", _, offset)) and
  not exists(string protectedSpan, int spanOffset |
    protectedSpan =
      stmt.regexpFind("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|\\$\\{\\{.*?\\}\\}", _,
        spanOffset) and
    spanOffset <= offset and
    offset < spanOffset + protectedSpan.length()
  ) and
  (offset = 0 or stmt.substring(offset - 1, offset) != "\\") and
  (offset = 0 or stmt.substring(offset - 1, offset) != "|") and
  (offset + 1 >= stmt.length() or stmt.substring(offset + 1, offset + 2) != "|")
}

/** Gets the offset of pipeline separator `k` in `stmt`. */
bindingset[stmt]
private int getPipelineSeparatorOffset(string stmt, int k) {
  result = rank[k + 1](int offset | isPipelineSeparator(stmt, offset) | offset)
}

/** Gets a stage of the pipeline in `stmt`, ignoring quoted pipes and Actions expressions. */
bindingset[stmt]
string getStage(string stmt, int k) {
  exists(string command |
    command = stmt.regexpReplaceAll("\\$\\([^()]*\\)|`[^`]*`|[<>]\\([^()]*\\)", "") and
    (
      k = 0 and
      (
        exists(int end |
          getPipelineSeparatorOffset(command, 0) = end and
          result = command.substring(0, end).trim()
        )
        or
        not exists(int end | getPipelineSeparatorOffset(command, 0) = end) and
        result = command.trim()
      )
      or
      k > 0 and
      exists(int start |
        getPipelineSeparatorOffset(command, k - 1) = start and
        (
          exists(int end |
            getPipelineSeparatorOffset(command, k) = end and
            result = command.substring(start + 1, end).trim()
          )
          or
          not exists(int end | getPipelineSeparatorOffset(command, k) = end) and
          result = command.substring(start + 1, command.length()).trim()
        )
      )
    )
  )
}

/** Holds if `stage` runs a tool that can encode its input, whichever mode it is in. */
bindingset[stage]
private predicate isEncodingTool(string stage) {
  stage
      .regexpMatch("(sudo\\s+)?(\\S*/)?(base64|base32|basenc|xxd|od|hexdump|rev|uuencode|openssl\\s+base64)(\\s.*)?")
  or
  // `openssl enc -base64` only encodes. With a cipher it encrypts, which hides the secret.
  stage.regexpMatch("(sudo\\s+)?(\\S*/)?openssl\\s+enc\\s+-(a|A|base64)(\\s.*)?") and
  not stage
      .regexpMatch(".*\\s-(aes|des|bf|camellia|chacha|rc[245]|seed|aria|sm4|cast)[a-z0-9-]*(\\s.*)?")
}

/** Holds if `stage` runs an encoding tool in its decoding mode, which restores data and hides nothing. */
bindingset[stage]
private predicate isDecodingMode(string stage) {
  stage
      .regexpMatch("(sudo\\s+)?(\\S*/)?(base64|base32|basenc)(\\s.*)?\\s(-[a-zA-Z]*[dD][a-zA-Z]*|--decode)(\\s.*)?")
  or
  stage.regexpMatch("(sudo\\s+)?(\\S*/)?xxd(\\s.*)?\\s-(r|rp|pr|revert)(\\s.*)?")
  or
  stage.regexpMatch("(sudo\\s+)?(\\S*/)?openssl\\s+(base64|enc)(\\s.*)?\\s-d(\\s.*)?")
}

/** Holds if `stage` is a command whose output is an encoded or transformed form of its input. */
bindingset[stage]
predicate isEncodingCommand(string stage) { isEncodingTool(stage) and not isDecodingMode(stage) }

/** Holds if `stage` forwards its input to the log unchanged, or changes only its form. */
bindingset[stage]
predicate isPassThroughCommand(string stage) {
  stage.regexpMatch("^(sudo\\s+)?(\\S*/)?(tee|tr)(\\s.*)?")
  or
  stage
      .regexpMatch("^(sudo\\s+)?(\\S*/)?(cat|fold)(\\s+(-|-[a-zA-Z0-9][a-zA-Z0-9-]*(\\s+[0-9]+)?))*\\s*$")
}

/** Holds if `stage` consumes secret arguments without forwarding them to stdout. */
bindingset[stage]
predicate isNonEmittingCommand(string stage) {
  stage.regexpMatch("^(sudo\\s+)?(\\S*/)?curl(\\s.*)?")
}

/** Holds if `stage` sends its standard output to a file. */
bindingset[stage]
predicate redirectsStdout(string stage) {
  stage.regexpMatch(".*(^|[^2])>{1,2}\\s*[^&\\s].*")
  or
  // an output option of the encoder, for example `base64 -o file` or `openssl base64 -out file`
  stage
      .regexpMatch("(sudo\\s+)?(\\S*/)?(base64|base32|basenc|openssl)(\\s.*)?\\s(-o|--output|-out)([\\s=].*)?")
}

/** Gets the name of a shell variable or environment variable referenced in `stage`. */
bindingset[stage]
string getAReferencedVariable(string stage) {
  result =
    stage
        .regexpReplaceAll("'(?:\\\\.|[^'\\\\])*'", "")
        .regexpReplaceAll("\\\\\\$", "")
        .regexpFind("\\$\\{?[a-zA-Z_][a-zA-Z0-9_]*", _, _)
        .regexpCapture("\\$\\{?(.*)", 1)
  or
  result =
    stage
        .regexpReplaceAll("'(?:\\\\.|[^'\\\\])*'", "")
        .regexpCapture("(?:\\S*/)?printenv\\s+([a-zA-Z_][a-zA-Z0-9_]*).*", 1)
}

/**
 * Holds if `secret` is a secret expression that the script of `run` can use, either inline or
 * through its environment.
 *
 * This is a predicate of its own so that the expensive text tests of `isSecretExpression` run once
 * per expression, and not once per combination of expression and statement.
 */
pragma[nomagic]
private predicate isSecretOfRun(Run run, Expression secret) {
  isSecretExpression(secret.getExpression()) and
  (secret = run.getAnScriptExpr() or secret = run.getInScopeEnvVarExpr(_))
}

/** Holds if `stage` in `run` references the secret expression `secret`. */
bindingset[run, useLine, stage]
predicate stageReferencesSecret(Run run, int useLine, string stage, Expression secret) {
  isSecretOfRun(run, secret) and
  (
    // inline secret expression: echo "${{ secrets.X }}" | base64
    secret = run.getAnScriptExpr() and
    stage.indexOf(secret.getRawExpression()) >= 0
    or
    exists(string var |
      var = getAReferencedVariable(stage) and
      stageReferencesVariableSecret(run, run.getScript(), useLine, var, secret)
    )
  )
}

/** Holds if a referenced variable resolves to a secret in its environment or latest assignment. */
bindingset[run, script, useLine, var]
predicate stageReferencesVariableSecret(
  Run run, ShellScript script, int useLine, string var, Expression secret
) {
  isSecretOfRun(run, secret) and
  (
    // environment variable: env: { X: ${{ secrets.X }} }
    secret = run.getInScopeEnvVarExpr(var)
    or
    // shell variable assigned from a secret: X="${{ secrets.X }}" or X="$SECRET_ENV"
    (
      secret = run.getAnScriptExpr() and
      getLatestAssignmentData(script, useLine, var).indexOf(secret.getRawExpression()) >= 0
      or
      secret =
        run.getInScopeEnvVarExpr(getAReferencedVariable(getLatestAssignmentData(script, useLine, var)))
    )
  )
}

/** Gets the data for the latest assignment to `var` before `useLine`. */
bindingset[script, useLine, var]
private string getLatestAssignmentData(ShellScript script, int useLine, string var) {
  exists(int assignmentLine, string assignmentStmt |
    assignmentStmt = script.getStmt(assignmentLine) and
    assignmentLine < useLine and
    script.getAssignment(assignmentLine, var, result) and
    not exists(int laterAssignmentLine, string laterStmt |
      laterStmt = script.getStmt(laterAssignmentLine) and
      script.getAssignment(laterAssignmentLine, var, _) and
      assignmentLine < laterAssignmentLine and
      laterAssignmentLine < useLine
    )
  )
}

/** Holds if `stage` provides the secret to the input of encoding stage `encodingStage`. */
bindingset[run, useLine, stageIndex, encodingStage, stage]
predicate stageProducesSecret(
  Run run, int useLine, int stageIndex, int encodingStage, string stage, Expression secret
) {
  stageReferencesSecret(run, useLine, stage, secret) and
  (
    stageIndex < encodingStage and not isNonEmittingCommand(stage)
    or
    stageIndex = encodingStage and stage.regexpMatch(".*<<<\\s*.*")
  )
}

/** Holds if statement `e` of `script` redirects the standard output of every later statement. */
pragma[nomagic]
private predicate execRedirectsStdout(ShellScript script, int e) {
  script.getStmt(e).regexpMatch("^exec\\s+(1?>{1,2}|&>{1,2})\\s*[^&\\s].*")
}

/** Holds if an earlier statement in `script` redirects the standard output of every later statement. */
bindingset[script, i]
predicate stdoutRedirectedByExec(ShellScript script, int i) {
  exists(int e | e < i and execRedirectsStdout(script, e))
}

/** Holds if statement `opener` of `script` starts a here-document that ends at a line `delimiter`. */
pragma[nomagic]
private predicate heredocOpener(ShellScript script, int opener, string delimiter) {
  exists(string stmt | stmt = script.getStmt(opener) and stmt.indexOf("<<") >= 0 |
    delimiter = stmt.regexpCapture(".*(?<!<)<<-?\\s*['\"\\\\]?([A-Za-z_][A-Za-z0-9_]*)['\"]?.*", 1)
  )
}

/** Holds if line `i` of `script` is inside a here-document body, which is data and not a command. */
bindingset[script, i]
predicate isInHeredocBody(ShellScript script, int i) {
  exists(int opener, string delimiter |
    opener < i and
    heredocOpener(script, opener, delimiter) and
    not exists(int closer |
      opener < closer and closer < i and script.getStmt(closer).trim() = delimiter
    )
  )
}

/**
 * Holds if `stmt`, statement `i` of the Bash script of `run`, mentions an encoding command.
 * The plain text test comes first so that the pipelines of other statements are never parsed.
 */
pragma[nomagic]
private predicate candidateStatement(Run run, int i, string stmt) {
  run.getScript() instanceof BashShellScript and
  stmt = run.getScript().getStmt(i) and
  stmt.regexpMatch(".*(base64|base32|basenc|xxd|\\bod\\b|hexdump|\\brev\\b|uuencode|openssl).*")
}

/** Gets stage `k` of the pipeline of the candidate statement `stmt`. */
pragma[nomagic]
private string stageOf(Run run, int i, string stmt, int k) {
  candidateStatement(run, i, stmt) and result = getStage(stmt, k)
}

/**
 * Holds if the script of `run` has an inline expression with the same text as `secret` before
 * `secret`. Statements are matched to expressions by text, so such a twin is indistinguishable
 * from `secret` and would only report the same alert again.
 */
bindingset[run, secret]
private predicate hasEarlierTwin(Run run, Expression secret) {
  exists(Expression earlier |
    secret = run.getAnScriptExpr() and
    earlier = run.getAnScriptExpr() and
    earlier.getRawExpression() = secret.getRawExpression() and
    (
      earlier.getLocation().getStartLine() < secret.getLocation().getStartLine()
      or
      earlier.getLocation().getStartLine() = secret.getLocation().getStartLine() and
      earlier.getLocation().getStartColumn() < secret.getLocation().getStartColumn()
    )
  )
}

from Run run, int i, string stmt, int j, Expression secret
where
  candidateStatement(run, i, stmt) and
  isEncodingCommand(stageOf(run, i, stmt, j)) and
  not hasEarlierTwin(run, secret) and
  not isInHeredocBody(run.getScript(), i) and
  not stdoutRedirectedByExec(run.getScript(), i) and
  // the statement is not the body of a command substitution, e.g. X="$(echo "$S" | base64)"
  not exists(string outer | outer = run.getScript().getStmt(i) |
    outer.indexOf("$(" + stmt + ")") >= 0 or
    outer.indexOf("`" + stmt + "`") >= 0
  ) and
  // the output is not captured in a variable
  not stmt.regexpMatch("^(export\\s+|local\\s+|declare\\s+)?[a-zA-Z0-9_]+=.*") and
  // the secret flows into the encoding command, through stages that keep it recoverable
  exists(int k | k <= j |
    stageProducesSecret(run, i, k, j, stageOf(run, i, stmt, k), secret) and
    forall(int m | m > k and m < j and exists(stageOf(run, i, stmt, m)) |
      isPassThroughCommand(stageOf(run, i, stmt, m)) or
      isEncodingCommand(stageOf(run, i, stmt, m))
    )
  ) and
  not exists(int k | k < j | redirectsStdout(stageOf(run, i, stmt, k))) and
  not exists(int k | k < j | isNonEmittingCommand(stageOf(run, i, stmt, k))) and
  // the encoded value reaches the log
  forall(int l | l > j and exists(stageOf(run, i, stmt, l)) |
    isPassThroughCommand(stageOf(run, i, stmt, l))
  ) and
  not exists(int l | l >= j | redirectsStdout(stageOf(run, i, stmt, l)))
select run.getScript(),
  "The secret $@ is encoded and printed to the workflow log, which bypasses secret masking.",
  secret, secret.getExpression()
