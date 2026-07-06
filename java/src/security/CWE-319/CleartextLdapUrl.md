# Cleartext LDAP URL

Configuring an LDAP context source with an `ldap://` URL transmits bind credentials and directory data over an unencrypted channel. An attacker positioned on the network can intercept the service-account password and the contents of every directory query and response.

## Recommendation
Use `ldaps://` (LDAP over TLS) or enable STARTTLS so that the connection to the directory server is encrypted and authenticated. Store the bind password outside source control (for example in a secret manager or environment variable).

## Example
The following example configures a Spring `LdapContextSource` with a cleartext `ldap://` URL, so the bind credentials cross the network in the clear.

```java
@Bean
public LdapContextSource ldapContextSource() {
    LdapContextSource ctx = new LdapContextSource();
    // BAD: cleartext ldap:// transmits the bind password unencrypted.
    ctx.setUrl("ldap://ldap.corp.example.com:389");
    ctx.setUserDn("cn=svc-app,ou=ServiceAccounts,dc=corp,dc=example,dc=com");
    ctx.setPassword(System.getenv("LDAP_PASSWORD"));
    ctx.afterPropertiesSet();
    return ctx;
}
```

Use `ldaps://ldap.corp.example.com:636` instead.

## References
* OWASP: [Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html).
* Common Weakness Enumeration: [CWE-319](https://cwe.mitre.org/data/definitions/319.html).
