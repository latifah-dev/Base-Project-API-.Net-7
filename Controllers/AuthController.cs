using System.Text;
using BASEAPI.Models;
using BASEAPI.Models.Dtos;
using BASEAPI.Models.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

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
            //send email 
            var verifylink = "http://localhost:5139/api/Auth/verify?token="+randomToken;
            var email  = new EmailDto() {
                To = register.Email,
                Subject = "VERIFICATION EMAIL",
                Body = "<br/><br/>We are excited to tell you that your account is" +  
      " successfully created. Please click on the below link to verify your account" +  
      " <br/><br/><a href='" + verifylink + "'>" + verifylink + "</a> ",
            };
            _emailservice.SendEmail(email);
            //response
            return Created("Register successly, check your email to verification !", NewUser);
        }
        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin()
        {
            var authenticationProperties = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(GoogleCallback))
            };

            return Challenge(authenticationProperties, "Google");
        }
        [HttpGet("google-callback")]
        public async Task<IActionResult> GoogleCallback(string returnUrl = "/")
        {
            var authenticateResult = await HttpContext.AuthenticateAsync("Google");
            if (!authenticateResult.Succeeded)
            {
                // Handle authentication failure
                return RedirectToAction("Login", "Account");
            }

            // If authentication is successful, create the identity and sign in the user
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, authenticateResult.Principal.FindFirst(ClaimTypes.NameIdentifier).Value),
                new Claim(ClaimTypes.Name, authenticateResult.Principal.FindFirst(ClaimTypes.Name).Value),
                new Claim(ClaimTypes.Email, authenticateResult.Principal.FindFirst(ClaimTypes.Email).Value),
            };

            var userIdentity = new ClaimsIdentity(claims, "login");
            var userPrincipal = new ClaimsPrincipal(userIdentity);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, userPrincipal);

            // Redirect user to the original URL
            return LocalRedirect(returnUrl);
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
            // definisikan klaim
            var claims = new List<Claim>
            {
                new Claim("sub", user.Id.ToString()), // sub (subject) adalah claim yang umum digunakan untuk menyatakan ID pengguna
                new Claim("email", user.Email), // contoh klaim email
                // tambahkan klaim lainnya di sini
            };
            // create jwt
            var secureKey = "this is very secure key";
            var symmetric = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secureKey));
            var credentials = new SigningCredentials(symmetric, SecurityAlgorithms.HmacSha256Signature);
            var header = new JwtHeader(credentials);
            var payload = new JwtPayload (null, null, claims, null, DateTime.Today.AddDays(1));
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
            
            //send email 
            var verifylink = "http://localhost:5139/api/Auth/forgot-password?email="+email+"/"+randomToken;
            var sendEmail  = new EmailDto() {
                To = email,
                Subject = "FORGOT PASSWORD",
                Body = "<br/><br/>Tap the link below to reset your account password." +  
      "  If you didn't request a new password, you can safely delete this email." +  
      " <br/><br/><a href='" + verifylink + "'>" + verifylink + "</a> ",
            };
            _emailservice.SendEmail(sendEmail);
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