# Audit: Usage of Insecure XML Parser

This query detects the use of insecure XML parsers in your C# code. Insecure XML parsers are parsers that do not have a secure configuration. If they are used to parse unsanitized user controlled input, they can be used to execute arbitrary code.
