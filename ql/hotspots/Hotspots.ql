/**
 * @name
 * @id githubsecuritylab/hotspots-query-generator
 * @description Finds all security-related TaintTracking sinks
 * @kind problem
 * @precision low
 */

import ql
import utils.hotspots

predicate debug_counts(int a, int b) {
  a = count(SecurityQuery q) and
  b = count(TaintTrackingSecurityQuery q)
}

predicate debug_missing(SecurityQuery q, string lang) {
  not exists(TaintTrackingSecurityQuery tq | tq = q) and q.getLanguage() = lang
}

predicate supportedLanguage(string lang) {
  lang = ["javascript", "java", "ruby", "csharp", "go", "python", "cpp"]
}

bindingset[severity]
predicate supportedSeverity(float severity) { severity > 7.0 or severity = -1.0 }

from TaintTrackingSecurityQuery q, TaintTrackingConfiguration c
where
  supportedLanguage(q.getLanguage()) and
  supportedSeverity(q.getSeverity()) and
  c = q.getTaintTrackingConfiguration()
// 1. language, 2. query id, 3. config path, 4. config name, 5. query import stmt, 6. query pack, 7. query severity, config kind, config isStateConfig
select q.getLanguage(), q.getId(), c.getPath(), c.getQualifiedName(), c.getImportStringFrom(q),
  c.getQLPack(), q.getSeverity().toString(), c.getKind(), c.isStateConfig()
