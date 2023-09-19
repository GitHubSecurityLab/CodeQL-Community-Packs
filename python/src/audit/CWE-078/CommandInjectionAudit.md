# Audit: Usage of Command Injection sink

This query detects the use of command injection sinks. Command injection sinks are functions that execute a command in a shell and if the command is constructed using user input, it may allow an attacker to execute arbitrary commands.
