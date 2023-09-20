/**
 * @name Files
 * @description List of all files in the repository
 * @kind table
 * @id githubsecuritylab/files
 * @tags audit
 */

import javascript

from File f
where f.getExtension() = ["js", "ts"] and not f.getRelativePath().matches("%/test/%")
select f.getRelativePath()
