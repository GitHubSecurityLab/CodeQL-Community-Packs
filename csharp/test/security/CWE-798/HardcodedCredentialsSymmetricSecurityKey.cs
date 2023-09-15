using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    [HttpPost("login")]
    public IActionResult Login(HttpContext ctx)
    {
        var user = ctx.Request.QueryString["user"];
        var password = ctx.Request.QueryString["password"];

        if (user is null || password is null)
        {
            return BadRequest("Invalid request");
        }

        if (user.UserName == "user" && user.Password == "password1234")   // BAD: Hardcoded credentials
        {
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("thisisasecretshhhhh")); // BAD: Hardcoded secret key
            var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
            var tokeOptions = new JwtSecurityToken(
                issuer: "https://localhost:8001",
                audience: "https://localhost:8001",
                claims: new List<Claim>(),
                expires: DateTime.Now.AddMinutes(1),
                signingCredentials: signingCredentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);

            return Ok(new AuthenticatedResponse { Token = tokenString });
        }

        return ctx.Response.Redirect("login");
    }
}
