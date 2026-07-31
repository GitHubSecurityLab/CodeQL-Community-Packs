# Audit - SQL Injection (any source, partial flow)

Dynamically generated SQL queries built from unvalidated data can cause SQL injection attacks.
This audit query does not restrict itself to recognized remote/user-controlled sources (like
`RemoteFlowSource`). Instead, it performs a partial (backwards) taint-tracking exploration from
every known SQL injection sink, up to a limited number of steps, so that it can surface data that
flows into a SQL query even when the originating source is not (yet) modeled as user input. This
makes it useful for triaging new or unusual sources of tainted data that reach a SQL injection
sink.

Because any node is considered a potential source, this query is very low precision and is
intended for manual audit, not for inclusion in a default security suite.

## Example

```java
import java.sql.Connection;
import java.sql.Statement;

public class Example {
  void run(Connection connection, String username) throws Exception {
    Statement statement = connection.createStatement();
    // Building a query by concatenating an unsanitized value is a SQL injection sink,
    // regardless of whether `username` is recognized as user input.
    statement.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
  }
}
```
