using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace BASEAPI.Models.Dtos
{
    public class RegisterDto
    {
        [Required]
        public string UserName {get; set;}
        [Required, EmailAddress]
        public string Email {get; set;}
        [Required, MinLength(6)]
        public string Password {get; set;}
        [Required, Compare("Password")]
        public string VerifyPassword {get; set;}
        [Required]
        public int Role {get; set;}
    }
}