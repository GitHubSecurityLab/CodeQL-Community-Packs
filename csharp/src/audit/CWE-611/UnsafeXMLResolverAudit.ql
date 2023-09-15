/**
 * @name Audit: Usage of Insecure XML Parser
 * @description XML may include dangerous external references, which should
 *              be restricted using a secure resolver or disabling DTD processing.
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.0
 * @precision low
 * @id cs/audit/insecure-xml-read
 * @tags security
 *       external/cwe/cwe-611
 *       external/cwe/cwe-827
 *       external/cwe/cwe-776
 *       audit
 */

// https://github.com/advanced-security/codeql-queries/blob/c8cfb6a0cc44da3d2baae4b985262a84652f71ee/csharp/ql/src/Security Features/CWE-611/UseXmlSecureResolver.ql#L22s
import csharp
import semmle.code.csharp.security.xml.InsecureXMLQuery

from InsecureXmlProcessing xmlProcessing, string reason
where xmlProcessing.isUnsafe(reason)
select xmlProcessing, "Insecure XML processing: " + reason
