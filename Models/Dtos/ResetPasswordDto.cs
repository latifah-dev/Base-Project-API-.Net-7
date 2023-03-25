using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace BASEAPI.Models.Dtos
{
    public class ResetPasswordDto
    {
        [Required]
        public string Token {get; set;}
        [Required, MinLength(6)]
        public string Password {get; set;}
        [Required, Compare("Password")]
        public string VerifyPassword {get; set;}
    }
}