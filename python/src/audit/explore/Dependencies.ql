/**
 * @name External dependencies
 * @description Count the number of dependencies that a Java project has on external packages.
 * @kind treemap
 * @id githubsecuritylab/external-dependencies
 * @metricType externalDependency
 * @tags audit
 */

import python
import semmle.python.dependencies.TechInventory

predicate package_count(ExternalPackage package, int total) {
  total = strictcount(AstNode src | dependency(src, package))
}

from ExternalPackage package, int total
where package_count(package, total)
select package.getName(), total order by total desc
