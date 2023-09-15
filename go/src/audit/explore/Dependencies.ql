/**
 * @name External dependencies
 * @description Count the number of dependencies that a Java project has on external packages.
 * @kind treemap
 * @id githubsecuritylab/external-dependencies
 * @metricType externalDependency
 * @tags audit
 */

import go
import semmle.go.dependencies.Dependencies

from Dependency d, int nimports, string name
where
  nimports = strictsum(ImportSpec is | is = d.getAnImport() | 1) and
  exists(string p, string v | d.info(p, v) and name = p + v)
select name, nimports order by nimports desc
