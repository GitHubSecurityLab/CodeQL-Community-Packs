/**
 * @name Audit: Usage of Unsafe Deserialize sink
 * @description Calling an unsafe deserializer with data controlled by an attacker
 *              can lead to denial of service and other security problems.
 * @kind problem
 * @id githubsecuritylab/audit/unsafe-deserialization
 * @problem.severity warning
 * @security-severity 2.0
 * @precision low
 * @tags security
 *       external/cwe/cwe-502
 *       audit
 */

import csharp
import semmle.code.csharp.security.dataflow.UnsafeDeserializationQuery

from DataFlow::Node sink
where sink instanceof Sink
select sink, "Usage of Unsafe Deserialize sink"
