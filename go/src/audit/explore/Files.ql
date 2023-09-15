import go

from File f
where f.getExtension() = "go" and not f.getRelativePath().matches("%/test/%")
select f.getRelativePath()
