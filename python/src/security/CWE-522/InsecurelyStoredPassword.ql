/**
 * @name Python insecurely stored password
 * @description Password stored insecurely directly in database without hashing with a secure password hash
 * @kind problem
 * @problem.severity error
 * @id githubsecuritylab/insecurely-stored-pw
 * @precision high
 * @tags password
 *       python
 *       external/cwe/cwe-256
 *       external/cwe/cwe-257
 *       external/cwe/cwe-522
 */

private import ghsl.InsecurelyStoredPassword

from User user
where not user.isSecure()
select user, "Insecure 'user' class $@ stores its password insecurely, without secure hashing",
  user, user.getName()
