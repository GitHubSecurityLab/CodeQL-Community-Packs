# Credentials transmitted in outbound request URL

Embedding a password or other secret in the URL of an outbound HTTP request exposes the credential in server logs, proxy logs, and browser history. When the request is sent over `http://` the credential also crosses the network in cleartext, where it can be intercepted.

## Recommendation
Send credentials in an `Authorization` header or a request body over a TLS-protected connection (`https://`), not as URL query parameters. Avoid logging full request URLs that contain secrets.

## Example
The following example concatenates a password into the query string of a request issued with a Spring `RestTemplate`.

```java
public String fetchReport(String reportName) {
    // BAD: the password is placed in the request URL.
    String url = props.getUrl()
            + "/Render?report=" + reportName
            + "&user=" + props.getUsername()
            + "&password=" + props.getPassword();
    return restTemplate.getForObject(url, String.class);
}
```

Send the credentials in a header instead, for example via `HttpHeaders.setBasicAuth(...)` over `https://`.

## References
* OWASP: [Information exposure through query strings in URL](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url).
* Common Weakness Enumeration: [CWE-598](https://cwe.mitre.org/data/definitions/598.html).
* Common Weakness Enumeration: [CWE-319](https://cwe.mitre.org/data/definitions/319.html).
