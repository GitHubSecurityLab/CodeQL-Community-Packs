# Record retrieval using a user-controlled identifier

A request-controlled identifier flows into a data-access lookup with no per-record ownership or authorization check, so an attacker can read another user's record simply by changing the identifier in the request. This is the read or disclosure sub-class of insecure direct object reference (IDOR).

This query is a heuristic. Review each result to confirm that the returned record is not subject to an ownership check elsewhere.

## Recommendation
Authorize the lookup against the authenticated caller: verify that the requested record belongs to (or is otherwise accessible by) the current user before returning it, or scope the query itself to the caller (for example `findByIdAndOwner(id, currentUser)`).

## Example
The following example reads a statement by its path id and returns it without checking that it belongs to the caller.

```java
@GetMapping("/{id}")
public AccountStatement getStatement(@PathVariable long id,
                                     @RequestHeader("X-User") String currentUser) {
    // BAD: currentUser is ignored; any id can be read.
    return service.getStatement(id);
}

// service -> repository
public AccountStatement getStatement(long id) {
    return repository.findById(id).orElseThrow();
}
```

Scope the lookup to the caller instead, for example `repository.findByIdAndOwnerUsername(id, currentUser)`.

## References
* OWASP: [Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html).
* OWASP Top 10: [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/).
* Common Weakness Enumeration: [CWE-639](https://cwe.mitre.org/data/definitions/639.html).
* Common Weakness Enumeration: [CWE-863](https://cwe.mitre.org/data/definitions/863.html).
