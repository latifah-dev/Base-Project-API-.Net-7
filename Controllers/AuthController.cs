using System.Text;
using BASEAPI.Models;
using BASEAPI.Models.Dtos;
using BASEAPI.Models.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;

namespace BASEAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;
        public AuthController(ApplicationDbContext dbContext) {
            _dbContext = dbContext;
        }

        [HttpPost]
        [Route("register")]
        public IActionResult Register(UserDto user) {
            var PasswordHasher = new PasswordHasher<string>();
            var hash = PasswordHasher.HashPassword(user.UserName, user.Password);

            var NewUser = new User() {
                UserName = user.UserName,
                Email = user.Email,
                Role = user.Role,
                Password = hash,
            };
            _dbContext.Users.Add(NewUser);
            _dbContext.SaveChanges();
            return Created("", NewUser);
        }
        [HttpPost]
        [Route("login")]
        public IActionResult Login(LoginDto login) {
            var user = _dbContext.Users.FirstOrDefault(x => x.UserName == login.UserNameOrEmail);
            
            if(user == null) {
                return Unauthorized("User does not exist");
            }

            
            var PasswordHasher = new PasswordHasher<string>();
            var verifPass = PasswordHasher.VerifyHashedPassword(login.UserNameOrEmail, user.Password, login.Password);
            if(verifPass == PasswordVerificationResult.Failed) {
                return Unauthorized("Incorrect password");
            }
            // create jwt
            var secureKey = "this is very secure key";
            var symmetric = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secureKey));
            var credentials = new SigningCredentials(symmetric, SecurityAlgorithms.HmacSha256Signature);
            var header = new JwtHeader(credentials);
            var payload = new JwtPayload (login.UserNameOrEmail, null, null, null,DateTime.Today.AddDays(1));
            var securityToken = new JwtSecurityToken(header, payload);
            var token = new JwtSecurityTokenHandler().WriteToken(securityToken);


            return Ok(new TokenDto {
                Access_Token = token,
                Token_Type = "Bearer",
                Expires = DateTime.UtcNow.AddDays(1),
            });
        }

    }
}