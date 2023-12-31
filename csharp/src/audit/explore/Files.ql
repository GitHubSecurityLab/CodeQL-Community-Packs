/**
 * @name Files
 * @description List of all files in the repository
 * @kind table
 * @id githubsecuritylab/files
 * @tags audit
 */

import csharp

from File f
where f.getExtension() = "cs" and not f.getRelativePath().matches("%/test/%")
select f.getRelativePath()
