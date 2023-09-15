# Audit: Usage of Command Injection sink

This query detects the use of command injection sinks in your C# code. Command injection sinks are methods that execute a command in a subprocess and if they use unsanitized input, they can be used to execute arbitrary commands.
