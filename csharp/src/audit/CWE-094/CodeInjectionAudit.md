# Audit: Use of Code Injection sink

This query detects the use of code injection sinks in your C# code. Code injection sinks are methods that execute code in a subprocess and if they use unsanitized input, they can be used to execute arbitrary code.
