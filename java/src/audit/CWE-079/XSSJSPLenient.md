# Cross-Site Scripting (XSS) in JSP (Lenient)

This query is similar to CWE-079/XSSJSP but is lenient with the analysis leading potentially to more results (including false positives).

## Summary

JSP or Java Server Pages is a technology that allows embedding Java code in HTML pages. It is used to generate dynamic web pages which can be injected with malicious code. This code can be executed by the browser of the user of the web application.

If the web application is vulnerable to XSS, the attacker can inject client-side scripts into the web pages and steal user cookies, session tokens, or other sensitive information retained by the browser and used with that site. These scripts can even rewrite the content of the HTML page.

## Example

The following example shows how a JSP page can be vulnerable to XSS:

```jsp
<$ out.println(request.getParameter("name")); $>
```

## How to Prevent

The following are some ways to prevent XSS in JSP:

```jsp
<$ out.println(Encode.forHtml(request.getParameter("name"))); $>
```

## References

* [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
