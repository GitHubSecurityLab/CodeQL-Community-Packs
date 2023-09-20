/**
 * @name Files
 * @description List of all files in the repository
 * @kind table
 * @id githubsecuritylab/files
 * @tags audit
 */

import cpp

from File f
where f.getExtension() = ["c", "cpp"] and not f.getRelativePath().matches("%/test/%")
select f.getRelativePath()
