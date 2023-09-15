# Hardcoded Salt

## Summary

Hardcoding a salt value in a cryptographic algorithm can make it easier for an attacker to crack the passwords. Even when using a strong algorithm, a salt should be randomly generated and stored with the password.

## Example

```csharp
public static string HashPassword(string password)
{
    byte[] salt = new byte[16];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(salt);
    }

    var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000);
    byte[] hash = pbkdf2.GetBytes(20);

    byte[] hashBytes = new byte[36];
    Array.Copy(salt, 0, hashBytes, 0, 16);
    Array.Copy(hash, 0, hashBytes, 16, 20);

    string savedPasswordHash = Convert.ToBase64String(hashBytes);

    return savedPasswordHash;
}
```
