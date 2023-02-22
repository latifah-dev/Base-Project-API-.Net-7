using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace BASEAPI.Models.Dtos
{
    public class UserDto
    {
        public string UserName {get; set;} = string.Empty;
        [EmailAddress]
        public string Email {get; set;} = string.Empty;
        public int Role {get; set;}
    }
}