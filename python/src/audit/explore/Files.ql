/**
 * @name Files
 * @description List of all files in the repository
 * @kind table
 * @id githubsecuritylab/files
 * @tags audit
 */

import python

from File f
where f.getExtension() = "py" and not f.getRelativePath().matches("%/test/%")
select f.getRelativePath()
