/**
 * @name Frequency counts for external APIs that are used with untrusted data
 * @description This reports the external APIs that are used with untrusted data, along with how
 *              frequently the API is called, and how many unique sources of untrusted data flow
 *              to it.
 * @id githubsecuritylab/count-untrusted-data-external-api
 * @kind table
 * @tags security external/cwe/cwe-20
 */

import csharp
import ExternalAPIsQuery

from ExternalApiUsedWithUntrustedData externalApi
select externalApi, count(externalApi.getUntrustedDataNode()) as numberOfUses,
  externalApi.getNumberOfUntrustedSources() as numberOfUntrustedSources order by
    numberOfUntrustedSources desc
