using System.Text;
using BASEAPI.Models;
using BASEAPI.Models.Dtos;
using BASEAPI.Models.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using MimeKit;
using MailKit.Net.Smtp;
using System.Security.Cryptography;

namespace BASEAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly IEmailService _emailservice;
        public AuthController(ApplicationDbContext dbContext, IEmailService emailservice) {
            _dbContext = dbContext;
            _emailservice = emailservice;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegisterDto register) {
            //validasi users
            if(_dbContext.Users.Any(u => u.UserName == register.UserName || u.Email == register.Email)) {
                return BadRequest("Users already axists.");
            }
            //hash password
            var PasswordHasher = new PasswordHasher<string>();
            var hash = PasswordHasher.HashPassword(register.UserName, register.VerifyPassword);
            //create token
            var randomToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
            //create new data to database
            var NewUser = new User() {
                UserName = register.UserName,
                Email = register.Email,
                Role = register.Role,
                Password = hash,
                VerificationToken = randomToken,
            };
            //save to database
            _dbContext.Users.Add(NewUser);
            await _dbContext.SaveChangesAsync();
            //response
            return Created("User successfully created !", NewUser);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(LoginDto login) {
            //find user
            var user = _dbContext.Users.FirstOrDefault(x => x.UserName == login.UserNameOrEmail || x.Email == login.UserNameOrEmail);
            //validasi users is ready
            if(user == null) {
                return Unauthorized("User does not exist");
            }
            //verify password hash
            var PasswordHasher = new PasswordHasher<string>();
            var verifPass = PasswordHasher.VerifyHashedPassword(login.UserNameOrEmail, user.Password, login.Password);
            if(verifPass == PasswordVerificationResult.Failed) {
                return BadRequest("Incorrect password");
            }
            //validasi users is verified
            if(user.VerifiedAt == null) {
                return BadRequest("not verified !");
            }
            // create jwt
            var secureKey = "this is very secure key";
            var symmetric = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secureKey));
            var credentials = new SigningCredentials(symmetric, SecurityAlgorithms.HmacSha256Signature);
            var header = new JwtHeader(credentials);
            var payload = new JwtPayload (login.UserNameOrEmail, null, null, null,DateTime.Today.AddDays(1));
            var securityToken = new JwtSecurityToken(header, payload);
            var token = new JwtSecurityTokenHandler().WriteToken(securityToken);
            //response
            return Ok(new TokenDto {
                Message = $"Welcome back, {user.UserName}",
                Access_Token = token,
                Token_Type = "Bearer",
                Expires = DateTime.UtcNow.AddDays(1),
            });
        }
        [HttpPost]
        [Route("verify")]
        public async Task<IActionResult> Verify(String token) {
            //find user
            var user = _dbContext.Users.FirstOrDefault(x => x.VerificationToken == token);
            //validasi user
            if(user == null) {
                return BadRequest("User does not exist");
            }
            //update date verified
            user.VerifiedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
            //response
            return Ok("user verified :)");
        }
        [HttpPost]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword(String email) {
            //find user
            var user = _dbContext.Users.FirstOrDefault(x => x.Email== email);
            if(user == null) {
                return BadRequest("User does not exist");
            }
            //create random token
             var randomToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
            user.PasswordResetToken = randomToken;
            user.ResetTokenExpires = DateTime.UtcNow.AddDays(1);
            await _dbContext.SaveChangesAsync();

            return Created("you may reset your token now", randomToken);
        }
        [HttpPost]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto reset) {
            //find user
            var user = _dbContext.Users.FirstOrDefault(x => x.PasswordResetToken == reset.Token);
            if(user == null || user.ResetTokenExpires < DateTime.UtcNow) {
                return BadRequest("Invalid Token");
            }
            //hash password
            var PasswordHasher = new PasswordHasher<string>();
            var hash = PasswordHasher.HashPassword(user.UserName, reset.VerifyPassword);
            
            user.Password = hash;
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;
            await _dbContext.SaveChangesAsync();
            return Ok("Password successly reset");
        }
        [HttpPost]
        [Route("email")]
        public IActionResult SendEmail(EmailDto request)
        {
            _emailservice.SendEmail(request);
            return Ok();
        }
    }

}