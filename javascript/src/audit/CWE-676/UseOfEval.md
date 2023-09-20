# Audit: Using JS Eval

This query detects the use of `eval` and `Function` in JavaScript code. `eval` and `Function` are functions that execute code and if the code is constructed using user input, it may allow an attacker to execute arbitrary code.
