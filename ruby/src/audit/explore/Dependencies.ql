/**
 * @name External dependencies
 * @description Count the number of dependencies that a Java project has on external packages.
 * @kind treemap
 * @id githubsecuritylab/external-dependencies
 * @metricType externalDependency
 * @tags audit
 */

import codeql.ruby.AST

from MethodCall c
where
  c.getLocation().getFile().getBaseName() = "Gemfile" and
  c.getMethodName() = "gem"
select c.getArgument(0), 1
