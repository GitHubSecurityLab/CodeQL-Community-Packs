# Audit: Usage of Unsafe Deserialize sink

This query detects the use of unsafe deserialize sinks in your C# code. Unsafe deserialize sinks are methods that deserialize data and if that data is unsanitized user controlled input, they can be used to execute arbitrary code.
