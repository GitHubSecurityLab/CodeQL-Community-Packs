/**
 * @name Insecure Functions
 * @description This query identifies the use of insecure functions in C++ code, such as `strcpy`, `strcat`, and `sprintf`, which can lead to buffer overflows and other vulnerabilities.
 * @id cpp/security/insecure-functions
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision high
 */

import cpp
import ghsl

predicate isInsecureFunction(FunctionCall call, string functionName) {
  functionName = call.getTarget().getName() and
  functionName in ["strcpy", "strcat", "sprintf", "gets", "scanf", "sscanf"]
}

from FunctionCall call, string functionName
where isInsecureFunction(call, functionName)
select call, "Insecure function '" + functionName + "' used. Consider using safer alternatives"
