/**
 * @name External dependencies
 * @description Count the number of dependencies that a Java project has on external packages.
 * @kind treemap
 * @id githubsecuritylab/external-dependencies
 * @metricType externalDependency
 * @tags audit
 */

import java
import semmle.code.java.DependencyCounts

predicate jarDependencyCount(int total, string entity) {
  exists(JarFile targetJar, string jarStem |
    jarStem = targetJar.getStem() and
    jarStem != "rt"
  |
    total =
      sum(RefType r, RefType dep, int num |
        r.fromSource() and
        not dep.fromSource() and
        dep.getFile().getParentContainer*() = targetJar and
        numDepends(r, dep, num)
      |
        num
      ) and
    entity = jarStem
  )
}

from string name, int ndeps
where jarDependencyCount(ndeps, name)
select name, ndeps order by ndeps desc
