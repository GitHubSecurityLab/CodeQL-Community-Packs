import java
from File f 
where f.getExtension() = "java" and not f.getRelativePath().matches("%/src/test/%")
select f.getRelativePath()
