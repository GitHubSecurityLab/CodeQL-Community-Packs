# Audit: Usage of Insecure XML Parser

This query detects the use of insecure XML parsers. Insecure XML parsers are parsers that do not prevent XML External Entity (XXE) attacks. If an XML parser is used to parse untrusted user input, it may allow an attacker to perform XXE attacks.
