# Audit - SQL Injection using format strings

Dynamically generated SQL queries using format strings can cause SQL injection attacks. The following example shows how to use the `sql` package to execute a query with a format string:

## Example

```python
# Format string
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# str.format()
query = "SELECT * FROM users WHERE username = '{}'".format(username)
cursor.execute(query)

# "%s" % string
query = "SELECT * FROM users WHERE username = %s" % username
cursor.execute(query)
```
