using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using BASEAPI.Models;
using BASEAPI.Models.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace BASEAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly IEmailService _emailservice;
        public UserController(ApplicationDbContext dbContext, IEmailService emailservice) {
            _dbContext = dbContext;
            _emailservice = emailservice;
        }
        [HttpGet]
        [Authorize]
        [Route("get-me")]
        public IActionResult GetMe() {
            var user = HttpContext.User;
            var Email = user.FindFirst(ClaimTypes.Email)?.Value;
            var currentUser = _dbContext.Users.FirstOrDefault(x => x.Email == Email);
            return Ok(currentUser);
        }
        [HttpPut]
        [Authorize]
        [Route("update-profile")]
        public async Task<IActionResult> UpdateProfile(UserDto update) {
            var user = HttpContext.User;
            var Email = user.FindFirst(ClaimTypes.Email)?.Value;
            var currentUser = _dbContext.Users.FirstOrDefault(x => x.Email == Email);
            if(currentUser == null) {
            return NotFound("User not found");
            }
            if(_dbContext.Users.Any(x => x.UserName == update.UserName && x.Id != currentUser.Id)) {
                return BadRequest("username already used");
            }
            if(!string.IsNullOrEmpty(update.Email) && _dbContext.Users.Any(x => x.Email == update.Email && x.Id != currentUser.Id)) {
                return BadRequest("email already used");
            }
            //update data in db
            currentUser.UserName = update.UserName;
                if (!string.IsNullOrEmpty(update.Email) && currentUser.Email != update.Email)
                {
                    currentUser.Email = update.Email;
                    //create token
                    var randomToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
                    currentUser.VerificationToken = randomToken;
                    currentUser.VerifiedAt = null;
                    var verifylink = "http://localhost:5139/api/Auth/verify?token="+randomToken;
                    var email  = new EmailDto() {
                        To = update.Email,
                        Subject = "VERIFICATION EMAIL",
                        Body = "<br/><br/>We are excited to tell you that your email is" +  
            " successfully changed. Please click on the below link to verify your account" +  
            " <br/><br/><a href='" + verifylink + "'>" + verifylink + "</a> ",
                    };
                    _emailservice.SendEmail(email);
                }
            currentUser.Role = update.Role;
            await _dbContext.SaveChangesAsync();
            return Ok(currentUser);
        }
        [HttpPut]
        [Authorize]
        [Route("change-password")]
        public async Task<IActionResult> ChangePassword(PasswordDto pass) {
            var user = HttpContext.User;
            var Email = user.FindFirst(ClaimTypes.Email)?.Value;
            var currentUser = _dbContext.Users.FirstOrDefault(x => x.Email == Email);
            //verify password hash
            var PasswordHasher = new PasswordHasher<string>();
            var verifPass = PasswordHasher.VerifyHashedPassword(Email, currentUser.Password, pass.OldPassword);
            if(verifPass == PasswordVerificationResult.Failed) {
                return BadRequest("Incorrect old password");
            }
            //hash password
            var hash = PasswordHasher.HashPassword(currentUser.UserName, pass.VerifyPassword);
            currentUser.Password = hash;
            await _dbContext.SaveChangesAsync();
            return Ok("Password Has been changed");
        }
        [HttpDelete]
        [Authorize]
        [Route("delete-account")]
        public async Task<IActionResult> DeleteAccount () {
            var user = HttpContext.User;
            var Email = user.FindFirst(ClaimTypes.Email)?.Value;
            var currentUser = _dbContext.Users.FirstOrDefault(x => x.Email == Email);
            _dbContext.Users.Remove(currentUser);
            await _dbContext.SaveChangesAsync();
            return Ok("account has been deleted !");
        }
    }
}