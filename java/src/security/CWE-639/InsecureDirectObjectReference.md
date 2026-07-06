# Insecure direct object reference

A web action that operates on a resource identified by user input, without checking that the current user is authorized to act on that specific resource, allows an attacker to access or modify arbitrary objects by changing the identifier.

This query is the Java analogue of the C# query `cs/web/insecure-direct-object-reference`. It flags a state-changing Spring controller action that takes an id-like parameter but performs no user or session check and carries no method-security annotation.

## Recommendation
Add an authorization check that ties the request to the authenticated user before acting on the resource. This can be a method-security annotation such as `@PreAuthorize` or `@PostAuthorize`, an explicit ownership check against the current user or session, or a query scoped to the caller.

## Example
The following example deletes a record identified by a path variable without verifying that the caller owns it.

```java
@DeleteMapping("/{id}")
public void deleteStatement(@PathVariable long id) {
    // BAD: no check that the current user may delete record `id`.
    service.delete(id);
}
```

Restrict the action with an authorization check, for example:

```java
@DeleteMapping("/{id}")
@PreAuthorize("@statementAccess.isOwner(#id, authentication.name)")
public void deleteStatement(@PathVariable long id) {
    service.delete(id);
}
```

## References
* OWASP: [Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html).
* OWASP Top 10: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/).
* Common Weakness Enumeration: [CWE-639](https://cwe.mitre.org/data/definitions/639.html).
