# Use of Insecure Functions

## Description

Insecure functions are those that can lead to vulnerabilities in the code, such as buffer overflows, format string vulnerabilities, or other security issues.
These functions may not perform adequate input validation or may allow for unsafe operations.

## Examples

### Insecure Function Usage

```cpp
#include <cstdio>
#include <cstring>

void vulnerable_examples() {
    char buffer[50];
    char source[100] = "This is a very long string that will overflow the buffer";

    // 1. strcpy - No bounds checking, can cause buffer overflow
    strcpy(buffer, source);  // VULNERABLE: source may be longer than buffer

    // 2. strcat - No bounds checking for concatenation
    char dest[10] = "Hello";
    strcat(dest, " World!");  // VULNERABLE: may overflow dest buffer

    // 3. sprintf - Can cause buffer overflow with format strings
    char formatted[20];
    sprintf(formatted, "User: %s, ID: %d", "VeryLongUsername", 12345);  // VULNERABLE

    // 4. gets - Reads unlimited input, always vulnerable
    char input[100];
    gets(input);  // VULNERABLE: no bounds checking whatsoever

    // 5. scanf with %s - No bounds checking
    char name[20];
    scanf("%s", name);  // VULNERABLE: user can input more than 20 characters

    // 6. sscanf with %s - Similar vulnerability as scanf
    char data[30];
    char line[] = "VeryLongStringThatExceedsBufferSize";
    sscanf(line, "%s", data);  // VULNERABLE: no bounds checking
}
```

### Secure Function Usage

```cpp
#include <cstdio>
#include <cstring>
#include <string>

void secure_examples() {
    char buffer[50];
    char source[100] = "This is a very long string that will overflow the buffer";

    // 1. Use strncpy instead of strcpy
    strncpy(buffer, source, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination

    // Alternative: Use std::string (C++)
    std::string safe_string = source;

    // 2. Use strncat instead of strcat
    char dest[20] = "Hello";
    strncat(dest, " World!", sizeof(dest) - strlen(dest) - 1);

    // Alternative: Use std::string concatenation
    std::string safe_dest = "Hello";
    safe_dest += " World!";

    // 3. Use snprintf instead of sprintf
    char formatted[50];
    int result = snprintf(formatted, sizeof(formatted), "User: %s, ID: %d", "Username", 12345);
    if (result >= sizeof(formatted)) {
        // Handle truncation
        printf("Warning: Output was truncated\n");
    }

    // 4. Use fgets instead of gets
    char input[100];
    if (fgets(input, sizeof(input), stdin) != NULL) {
        // Remove newline if present
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n') {
            input[len-1] = '\0';
        }
    }

    // Alternative: Use std::getline (C++)
    std::string safe_input;
    std::getline(std::cin, safe_input);

    // 5. Use scanf with field width specifier
    char name[20];
    scanf("%19s", name);  // Limit input to 19 characters + null terminator

    // Better alternative: Use fgets
    if (fgets(name, sizeof(name), stdin) != NULL) {
        // Remove newline if present
        size_t len = strlen(name);
        if (len > 0 && name[len-1] == '\n') {
            name[len-1] = '\0';
        }
    }

    // 6. Use sscanf with field width specifier
    char data[30];
    char line[] = "VeryLongStringThatExceedsBufferSize";
    sscanf(line, "%29s", data);  // Limit to 29 characters + null terminator
}

// Modern C++ approach using safe containers
void modern_cpp_approach() {
    // Use std::string for dynamic strings
    std::string user_input;
    std::getline(std::cin, user_input);

    // Use std::vector for dynamic arrays
    std::vector<char> buffer(100);

    // Use standard library algorithms
    std::string source = "Hello";
    std::string dest = "World";
    std::string result = source + " " + dest;  // Safe concatenation
}
```

## Common Vulnerability Patterns

1. **Buffer Overflows**: Functions like `strcpy`, `strcat`, and `sprintf` don't check buffer boundaries
2. **Format String Vulnerabilities**: Using user input directly in format strings
3. **Unbounded Input**: Functions like `gets` and `scanf("%s", ...)` can read unlimited input
4. **Missing Null Termination**: Functions like `strncpy` may not null-terminate strings

## Best Practices

- Always use bounded versions of string functions (`strncpy`, `strncat`, `snprintf`)
- Specify field widths when using `scanf` family functions
- Consider using C++ `std::string` and containers for automatic memory management
- Validate input lengths before processing
- Always null-terminate strings when using bounded functions
- Use static analysis tools like CodeQL to identify these patterns automatically
