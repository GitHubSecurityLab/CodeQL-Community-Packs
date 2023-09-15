/**
 * @name Files
 * @description List of all files in the repository
 * @kind table
 * @id githubsecuritylab/files
 * @tags audit
 */

import java

from File f
where f.getExtension() = "java" and not f.getRelativePath().matches("%/src/test/%")
select f.getRelativePath()
