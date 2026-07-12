# JDBC connection disables TLS certificate validation

A JDBC URL containing `trustServerCertificate=true` makes the driver accept any server certificate. Even when the URL also sets `encrypt=true`, the channel is then encrypted but unauthenticated, so a man-in-the-middle can present its own certificate, impersonate the database, and read or modify all traffic, including credentials.

## Recommendation
Remove `trustServerCertificate=true` and let the driver validate the server certificate against a trusted certificate authority. If the database uses a private CA, import that CA into the client trust store rather than disabling validation.

## Example
The following example builds a SQL Server JDBC URL that disables certificate validation.

```java
// BAD: trustServerCertificate=true accepts any certificate (MITM risk).
private static final String JDBC_URL =
        "jdbc:sqlserver://db01.corp.example.com:1433;databaseName=App;"
                + "encrypt=true;trustServerCertificate=true;loginTimeout=5";

try (Connection c = DriverManager.getConnection(JDBC_URL, user, password)) {
    // ...
}
```

Use `encrypt=true;trustServerCertificate=false` and trust the server certificate through the client trust store.

## References
* Microsoft: [Connecting with encryption (JDBC driver for SQL Server)](https://learn.microsoft.com/en-us/sql/connect/jdbc/connecting-with-ssl-encryption).
* Common Weakness Enumeration: [CWE-295](https://cwe.mitre.org/data/definitions/295.html).
