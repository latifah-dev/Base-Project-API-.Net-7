using BASEAPI.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace BASEAPI.Models
{
    public class ApplicationDbContext:DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext>options):base(options) {
            
        }
        public DbSet<User>Users{get; set;}
    }
}