/**
 * @name Files
 * @description List of all files in the repository
 * @kind table
 * @id githubsecuritylab/files
 * @tags audit
 */

import ruby

from File f
where f.getExtension() = "rb" and not f.getRelativePath().matches("%/test/%")
select f.getRelativePath()
