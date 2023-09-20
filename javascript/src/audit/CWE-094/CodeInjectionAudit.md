# Audit: Usage of Code Injection sink

This query detects the usage of code injection sinks. Code injection sinks are functions that execute arbitrary JavaScript and if the commands are constructed using user input, it may allow an attacker to execute arbitrary JavaScript in the browser (XSS) or server-side code (Remote Code Execution).
