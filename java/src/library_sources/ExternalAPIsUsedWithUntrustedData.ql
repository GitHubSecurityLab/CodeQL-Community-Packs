import java
import semmle.code.java.dataflow.DataFlow
import ExternalAPIs

from ExternalApiUsedWithUntrustedData externalApi
select externalApi, count(externalApi.getUntrustedDataNode()) as numberOfUses,
  externalApi.getNumberOfUntrustedSources() as numberOfUntrustedSources order by
    numberOfUntrustedSources desc
