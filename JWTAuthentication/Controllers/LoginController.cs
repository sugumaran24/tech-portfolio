using JWTAuthentication.Data;
using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;  // EF Core namespace
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.IO;

namespace JWTAuthentication.Controllers
{
    [Route("/[controller]")]
    [ApiController]
    public class LoginController : Controller
    {
        private readonly IConfiguration _config;
        private readonly ILogger<LoginController> _logger;
        private readonly ApplicationDbContext _dbContext;  // <-- inject your DB context

        public LoginController(IConfiguration config, ILogger<LoginController> logger, ApplicationDbContext dbContext)
        {
            _config = config;
            _logger = logger;
            _dbContext = dbContext;
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] UserModel login)
        {
            try
            {
                // Validate model-level nulls
                if (login == null)
                    return BadRequest("Request body is required.");

                // Read raw body again to validate extra fields
                Request.EnableRewind(); // Enable buffering for .NET Core 2.1
                Request.Body.Position = 0;

                using (var reader = new StreamReader(Request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true))
                {
                    var rawBody = await reader.ReadToEndAsync();
                    Request.Body.Position = 0;

                    var allowedFields = new[] { "Username", "Password", "APIKey" };
                    var json = JObject.Parse(rawBody);
                    var extraFields = json.Properties()
                                          .Select(p => p.Name)
                                          .Except(allowedFields, StringComparer.OrdinalIgnoreCase)
                                          .ToList();

                    if (extraFields.Any())
                        return BadRequest($"Unexpected field(s): {string.Join(", ", extraFields)}");
                }

                var hasApiKey = !string.IsNullOrWhiteSpace(login.APIKey);
                var hasUsernamePassword = !string.IsNullOrWhiteSpace(login.Username) && !string.IsNullOrWhiteSpace(login.Password);

                if ((hasApiKey && hasUsernamePassword) || (!hasApiKey && !hasUsernamePassword))
                    return BadRequest("Provide either API key or username/password — not both or neither.");

                var user = await AuthenticateUserAsync(login);
                if (user == null)
                {
                    _logger.LogWarning("Unauthorized login attempt detected for user: {Username}", login.Username);
                    return StatusCode(StatusCodes.Status401Unauthorized, new { message = "Unauthorized" });
                }

                _logger.LogInformation("User '{Username}' authenticated successfully.", user.Username);
                var tokenString = GenerateJSONWebToken(user);

                return Ok(new { accessToken = tokenString, tokenType = "Bearer" });
            }
            catch (JsonReaderException)
            {
                return BadRequest("Malformed JSON payload.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception during login.");
                return StatusCode(500, "An unexpected error occurred. Please try again later.");
            }
        }


        private string GenerateJSONWebToken(UserModel userInfo)
        {
            var securityKey = _config["Jwt:Key"];
            var issuer = _config["Jwt:Issuer"];
            var audience = _config["Jwt:Audience"];

            if (string.IsNullOrWhiteSpace(securityKey))
            {
                _logger.LogError("JWT Key is missing in configuration.");
                throw new InvalidOperationException("JWT Key is missing in configuration.");
            }
            if (string.IsNullOrWhiteSpace(issuer))
            {
                _logger.LogError("JWT Issuer is missing in configuration.");
                throw new InvalidOperationException("JWT Issuer is missing in configuration.");
            }
            if (string.IsNullOrWhiteSpace(audience))
            {
                _logger.LogError("JWT Audience is missing in configuration.");
                throw new InvalidOperationException("JWT Audience is missing in configuration.");
            }

            var key = Encoding.UTF8.GetBytes(securityKey);
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            List<Claim> claims = null;

            // Only add claims if ApiKey is null
            if (string.IsNullOrWhiteSpace(userInfo.APIKey))
            {
                claims = new List<Claim>
            {
                 new Claim(JwtRegisteredClaimNames.Sub, userInfo.Username),
                new Claim(ClaimTypes.Name, userInfo.Username)
            };

                if (!string.IsNullOrWhiteSpace(userInfo.roles))
                    claims.Add(new Claim(ClaimTypes.Role, userInfo.roles));
            }

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims, // Can be null if ApiKey is present
                expires: DateTime.Now.AddMinutes(720),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<UserModel> AuthenticateUserAsync(UserModel login)
        {
            if (login == null)
                return null;

            var hasApiKey = !string.IsNullOrWhiteSpace(login.APIKey);
            var hasUsernamePassword = !string.IsNullOrWhiteSpace(login.Username) && !string.IsNullOrWhiteSpace(login.Password);

            // Validation: Either API key OR username/password must be provided, not both or neither
            if ((hasApiKey && hasUsernamePassword) || (!hasApiKey && !hasUsernamePassword))
            {
                return null; // Or throw new InvalidOperationException("Provide either API key or username/password, not both or neither.");
            }

            // API Key authentication
            var configuredApiKey = _config["Jwt:ApiKey"];
            if (string.IsNullOrWhiteSpace(login.Username) && string.IsNullOrWhiteSpace(login.Password) && !string.IsNullOrWhiteSpace(login.APIKey) && string.Equals(login.APIKey, configuredApiKey, StringComparison.OrdinalIgnoreCase))
            {
                    return new UserModel
                    {
                        APIKey= login.APIKey
                    };
            }

            // Username/Password authentication
            if (login == null || string.IsNullOrWhiteSpace(login.Username) || string.IsNullOrWhiteSpace(login.Password))
                return null;

            var userEntity = await _dbContext.AspnetUsers
                .Include(u => u.Membership)
                .FirstOrDefaultAsync(u => u.UserName == login.Username);

            if (userEntity == null || userEntity.Membership == null)
                return null;

            var passwordFormat = userEntity.Membership.PasswordFormat;
            var storedPassword = userEntity.Membership.Password;
            var salt = userEntity.Membership.PasswordSalt;

            bool isValidPassword;

            if (passwordFormat == 1)
            {
                isValidPassword = VerifyPassword(login.Password, storedPassword, salt);
            }
            else if (passwordFormat == 0)
            {
                isValidPassword = login.Password == storedPassword;
            }
            else
            {
                isValidPassword = false;
            }

            if (!isValidPassword)
                return null;

            // Fetch user roles
            var userRoles = await (from ur in _dbContext.AspnetUsersInRoles
                                   join r in _dbContext.AspnetRoles on ur.RoleId equals r.RoleId
                                   where ur.UserId == userEntity.UserId
                                   select r.RoleName).ToListAsync();

            string rolesString = string.Join(",", userRoles);

            return new UserModel
            {
                Username = userEntity.UserName,
                roles = rolesString
            };
        }


        private bool VerifyPassword(string enteredPassword, string storedPassword, string salt)
        {
            using (var sha1 = System.Security.Cryptography.SHA1.Create())
            {
                var saltBytes = Convert.FromBase64String(salt);
                var passwordBytes = Encoding.Unicode.GetBytes(enteredPassword);

                // Combine salt + password bytes
                var combinedBytes = new byte[saltBytes.Length + passwordBytes.Length];
                Buffer.BlockCopy(saltBytes, 0, combinedBytes, 0, saltBytes.Length);
                Buffer.BlockCopy(passwordBytes, 0, combinedBytes, saltBytes.Length, passwordBytes.Length);

                var hashBytes = sha1.ComputeHash(combinedBytes);
                var computedHashBase64 = Convert.ToBase64String(hashBytes);

                return storedPassword == computedHashBase64;
            }
        }


    }
}
