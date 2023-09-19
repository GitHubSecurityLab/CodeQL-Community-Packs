/**
 * @name Audit: Usage of Dangerous Functions
 * @description Dangerous Functions
 * @kind problem
 * @id py/audit/dangerous-functions
 * @problem.severity warning
 * @security-severity 2.5
 * @sub-severity low
 * @precision low
 * @tags security
 *       external/cwe/cwe-676
 *       audit
 */

import python
import semmle.python.ApiGraphs

abstract private class DangerousFunctions extends DataFlow::Node { }

// https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b312-telnetlib
class Telnet extends DangerousFunctions {
  Telnet() {
    exists(DataFlow::Node call |
      // https://docs.python.org/3/library/telnetlib.html
      call = API::moduleImport("telnetlib").getMember("Telnet").getAValueReachableFromSource() and
      this = call
    )
  }
}

// https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b321-ftplib
class Ftp extends DangerousFunctions {
  Ftp() {
    exists(DataFlow::Node call |
      (
        // https://docs.python.org/3/library/ftplib.html
        call = API::moduleImport("ftplib").getMember("FTP").getAValueReachableFromSource()
        or
        call = API::moduleImport("ftplib").getMember("FTP_TLS").getAValueReachableFromSource()
      ) and
      this = call
    )
  }
}

// https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b306-mktemp-q
class TempFile extends DangerousFunctions {
  TempFile() {
    exists(DataFlow::Node call |
      call = API::moduleImport("tempfile").getMember("mktemp").getACall() and this = call
    )
  }
}

// https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b325-tempnam
class TempNam extends DangerousFunctions {
  TempNam() {
    exists(DataFlow::Node call |
      (
        call = API::moduleImport("os").getMember("tempnam").getACall()
        or
        call = API::moduleImport("os").getMember("tmpnam").getACall()
      ) and
      this = call
    )
  }
}

from DangerousFunctions funcs
select funcs.asExpr(), "Using potentially Dangerous Imports and Functions."
