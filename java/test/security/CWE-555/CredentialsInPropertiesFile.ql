/*
 * Note this is similar to src/security/CWE-555/CredentialsInPropertiesFile.ql
 * except we do not filter out test files.
 */

import java
import semmle.code.java.frameworks.CredentialsInPropertiesFile

from CredentialsConfig cc
select cc, cc.getConfigDesc()
