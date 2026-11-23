# Server-side request forgery (extended framework coverage)

Directly incorporating user input into the URL of an outgoing HTTP request can make the server send requests to destinations chosen by an attacker, for example internal services or cloud metadata endpoints. The response may then be reflected back to the attacker.

This query extends the standard `rust/request-forgery` query with:

- `iron` request sources: reads of the `url`, `headers` and `body` fields of an inbound `iron::request::Request`. The authority of `req.url` is derived from the attacker-controlled `Host` header.
- Flow of captured variables into `async` blocks, such as a `warp` `Filter::then` closure parameter used inside `async move { ... }`.
- A barrier for `format!` templates that start with a fixed scheme and host (for example `"https://my.app/{}"`), because interpolated values cannot change the destination host.

## Recommendation

Do not let user input select the scheme, host or port of an outgoing request. Use a fixed base URL and only append validated path or query components, or check the destination against an allowlist of permitted hosts.

## Example

In the following example, a URL path parameter is used as the host of an outgoing request:

```rust
let routes = warp::path::param().then(|tainted_param: String| async move {
    reqwest::Client::new()
        .post(format!("https://{}", tainted_param)) // BAD
        .send()
        .await
});
```

The following example only uses the parameter in the path of a request to a fixed host:

```rust
let routes = warp::path::param().then(|tainted_param: String| async move {
    reqwest::Client::new()
        .post(format!("https://my.app/{}", tainted_param)) // GOOD
        .send()
        .await
});
```

## References

- OWASP: [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).
- Common Weakness Enumeration: [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
