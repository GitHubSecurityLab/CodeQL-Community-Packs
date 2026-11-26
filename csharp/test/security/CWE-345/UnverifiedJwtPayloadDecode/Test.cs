using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace JwtTests
{
    public class JwtPayload
    {
        public string Username { get; set; }
        public IList<string> Roles { get; set; }

        // BAD: the payload segment is base64-decoded and its claims are trusted
        // without checking the token signature.
        public static JwtPayload ParseJwt(string jwt)
        {
            var jwtPayloadBase64 = jwt.Split('.')[1]; // $ Source
            if (jwtPayloadBase64.Length % 4 != 0)
            {
                jwtPayloadBase64 = jwtPayloadBase64.PadRight(jwtPayloadBase64.Length + (4 - jwtPayloadBase64.Length % 4), '=');
            }

            var json = Encoding.UTF8.GetString(Convert.FromBase64String(jwtPayloadBase64)); // $ Alert
            var doc = JObject.Parse(json);
            return new JwtPayload
            {
                Username = (string)doc["username"],
                Roles = doc["roles"].Values<string>().ToList()
            };
        }
    }

    public class AuthService
    {
        // BAD: base64url payload normalized with Replace before decoding.
        public bool IsAdmin(string token)
        {
            var parts = token.Split(".");
            var payload = parts[1].Replace('-', '+').Replace('_', '/'); // $ Source
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload)); // $ Alert
            return json.Contains("\"role\":\"admin\"");
        }

        // BAD: reading the signature for logging does not verify it.
        public bool IsAdminWithLoggedSignature(string token)
        {
            var parts = token.Split('.');
            Console.WriteLine(parts[2]);
            var json = Base64UrlEncoder.Decode(parts[1]); // $ Alert
            return json.Contains("\"role\":\"admin\"");
        }

        // BAD: Base64UrlEncoder.Decode on the payload segment.
        public string GetSubject(string token)
        {
            string[] parts = token.Split('.');
            var json = Base64UrlEncoder.Decode(parts[1]); // $ Alert
            return (string)JObject.Parse(json)["sub"];
        }

        // BAD: Base64UrlEncoder.DecodeBytes on the payload segment.
        public string GetSubjectFromBytes(string token)
        {
            var parts = token.Split('.');
            var json = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1])); // $ Alert
            return (string)JObject.Parse(json)["sub"];
        }

        // BAD: WebEncoders.Base64UrlDecode on the payload segment.
        public string GetSubjectWithWebEncoders(string token)
        {
            var parts = token.Split('.');
            var json = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(parts[1])); // $ Alert
            return (string)JObject.Parse(json)["sub"];
        }

        // BAD: Convert.TryFromBase64String on the payload segment.
        public string GetSubjectWithTryDecode(string token)
        {
            var parts = token.Split('.');
            var buffer = new byte[1024];
            if (!Convert.TryFromBase64String(parts[1], buffer, out var written)) // $ Alert
            {
                return null;
            }
            return (string)JObject.Parse(Encoding.UTF8.GetString(buffer, 0, written))["sub"];
        }

        // BAD: the payload segment reaches the decoder through a helper method.
        public string GetRoleViaHelper(string token)
        {
            var segments = token.Split('.');
            var json = DecodeSegment(segments[1]); // $ Source
            return (string)JObject.Parse(json)["role"];
        }

        private static string DecodeSegment(string segment)
        {
            var padded = segment.PadRight(segment.Length + (4 - segment.Length % 4) % 4, '=');
            return Encoding.UTF8.GetString(Convert.FromBase64String(padded)); // $ Alert
        }

        // GOOD: only the header segment is decoded, for example to read the "kid".
        public string GetKeyId(string token)
        {
            var parts = token.Split('.');
            var header = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[0]));
            return (string)JObject.Parse(header)["kid"];
        }

        // GOOD: the signature segment is verified before the payload is decoded.
        public string GetRoleVerified(string token, byte[] key)
        {
            var parts = token.Split('.');
            using var hmac = new HMACSHA256(key);
            var expected = hmac.ComputeHash(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]));
            var actual = Base64UrlEncoder.DecodeBytes(parts[2]);
            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            {
                throw new UnauthorizedAccessException();
            }
            var json = Base64UrlEncoder.Decode(parts[1]);
            return (string)JObject.Parse(json)["role"];
        }

        // GOOD: the signature segment is compared with an expected signature.
        public string GetRoleComparedSignature(string token, byte[] key)
        {
            var parts = token.Split('.');
            using var hmac = new HMACSHA256(key);
            var expected = Base64UrlEncoder.Encode(hmac.ComputeHash(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1])));
            if (expected != parts[2])
            {
                throw new UnauthorizedAccessException();
            }
            var json = Base64UrlEncoder.Decode(parts[1]);
            return (string)JObject.Parse(json)["role"];
        }

        // GOOD: the token is validated by a JWT library and claims are read from the result.
        public string GetRoleValidated(string token, byte[] key)
        {
            var handler = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            ClaimsPrincipal principal = handler.ValidateToken(token, parameters, out _);
            return principal.FindFirstValue("role");
        }

        // GOOD: the same token is validated with signing key validation enabled before decoding.
        public string GetRoleValidatedAndDecoded(string token, byte[] key)
        {
            var handler = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            handler.ValidateToken(token, parameters, out _);
            var parts = token.Split('.');
            return Base64UrlEncoder.Decode(parts[1]);
        }

        // BAD: the payload is decoded before the token is validated.
        public string GetRoleDecodedBeforeValidation(string token, byte[] key)
        {
            var handler = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            var parts = token.Split('.');
            var json = Base64UrlEncoder.Decode(parts[1]); // $ Alert
            handler.ValidateToken(token, parameters, out _);
            return json;
        }

        // BAD: ValidateToken alone does not establish signature validation.
        public string GetRoleWithUnvalidatedParameters(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = false
            };
            handler.ValidateToken(token, parameters, out _);
            var parts = token.Split('.');
            return Base64UrlEncoder.Decode(parts[1]); // $ Alert
        }

        // GOOD: async validation is followed by a guard for an invalid result.
        public async Task<string> GetRoleValidatedAsyncAndDecoded(string token, byte[] key)
        {
            var handler = new JsonWebTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            var validation = await handler.ValidateTokenAsync(token, parameters);
            if (!validation.IsValid)
            {
                throw new UnauthorizedAccessException();
            }
            var parts = token.Split('.');
            return Base64UrlEncoder.Decode(parts[1]);
        }

        // BAD: the result of async validation is not checked before decoding.
        public async Task<string> GetRoleWithoutAsyncValidationGuard(string token, byte[] key)
        {
            var handler = new JsonWebTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            var validation = await handler.ValidateTokenAsync(token, parameters);
            var parts = token.Split('.');
            return Base64UrlEncoder.Decode(parts[1]); // $ Alert
        }

        // GOOD: not a JWT, the string is not split on '.'.
        public byte[] DecodeSecondField(string csv)
        {
            var fields = csv.Split(',');
            return Convert.FromBase64String(fields[1]);
        }
    }
}
