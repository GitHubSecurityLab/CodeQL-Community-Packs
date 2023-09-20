# Audit: Usage of Unsafe Deserialize sink

This query detects the use of unsafe deserialize sinks. Unsafe deserialize sinks are functions that deserialize data and if the data is constructed using user input, it may allow an attacker to execute arbitrary code.
