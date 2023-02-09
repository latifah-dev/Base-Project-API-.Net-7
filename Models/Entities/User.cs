using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BASEAPI.Models.Entities
{
    public class User
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id {get; set; }
        public string UserName {get; set;}
        public string Email {get; set;}
        public string Password {get; set;}
        public int Role {get; set;}
    }
}