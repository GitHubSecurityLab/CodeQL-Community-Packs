# Audit: Cross-Site Scripting (XSS) sink in Flask using Jinja2 templates

This query detects the use of XSS sinks in Flask using Jinja2 templates. XSS sinks are functions that render user input as HTML and if the input is not properly sanitized, it may allow an attacker to execute arbitrary JavaScript code.

## Disclaimer

CodeQL does not support Jinja2 templates out of the box so it does not follow the the data to the Jinja2 sink. It is not guaranteed to find all XSS sinks in Flask applications.
