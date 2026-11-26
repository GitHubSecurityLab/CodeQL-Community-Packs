public static IEnumerable<string> GetRoles(string jwt, SecurityKey key)
{
    var parameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidIssuer = "https://issuer.example",
        ValidAudience = "my-api"
    };
    var principal = new JwtSecurityTokenHandler().ValidateToken(jwt, parameters, out _); // GOOD
    return principal.FindAll(ClaimTypes.Role).Select(c => c.Value);
}
