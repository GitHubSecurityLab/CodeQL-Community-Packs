/**
 * @name External dependencies
 * @description Count the number of dependencies that a Java project has on external packages.
 * @kind treemap
 * @id githubsecuritylab/external-dependencies
 * @metricType externalDependency
 * @tags audit
 */

private import csharp
private import semmle.code.csharp.dispatch.Dispatch
private import Telemetry.ExternalApi

private predicate getRelevantUsages(string namespace, int usages) {
  usages =
    strictcount(Call c, ExternalApi api |
      c.getTarget().getUnboundDeclaration() = api and
      api.getNamespace() = namespace
    )
}

private int getOrder(string namespace) {
  namespace =
    rank[result](string i, int usages | getRelevantUsages(i, usages) | i order by usages desc, i)
}

from ExternalApi api, string namespace, int usages
where
  namespace = api.getNamespace() and
  getRelevantUsages(namespace, usages) and
  getOrder(namespace) <= resultLimit()
select namespace, usages order by usages desc
