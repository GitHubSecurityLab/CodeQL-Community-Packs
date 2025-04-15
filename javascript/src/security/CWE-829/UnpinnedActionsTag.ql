/**
 * @name Unpinned tag for 3rd party Action in workflow
 * @description Using a tag for a 3rd party Action that is not pinned to a commit can lead to executing an untrusted Action through a supply chain attack.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.3
 * @precision high
 * @id githubsecuritylab/actions/unpinned-tag
 * @tags actions
 *       security
 *       deprecated
 *       external/cwe/cwe-829
 */

import javascript
import semmle.javascript.Actions

bindingset[version]
private predicate isPinnedCommit(string version) { version.regexpMatch("^[A-Fa-f0-9]{40}$") }

bindingset[repo]
private predicate isTrustedOrg(string repo) {
  exists(string org | org in ["actions", "github", "advanced-security"] | repo.matches(org + "/%"))
}

from
  Actions::Step step, Actions::Uses uses, string repo, string version, Actions::Workflow workflow,
  string name
where
  step.getUses() = uses and
  uses.getGitHubRepository() = repo and
  uses.getVersion() = version and
  workflow.getJob(_).getStep(_) = step and
  (
    workflow.getName() = name
    or
    not exists(workflow.getName()) and workflow.getFileName() = name
  ) and
  not isPinnedCommit(version) and
  not isTrustedOrg(repo)
select step,
  "Unpinned 3rd party Action '" + name + "' step $@ uses '" + repo + "' with ref '" + version +
    "', not a pinned commit hash", step, step.toString()
