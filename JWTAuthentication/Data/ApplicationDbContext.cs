using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using JWTAuthentication.Models;
using static Microsoft.ApplicationInsights.MetricDimensionNames.TelemetryContext;

namespace JWTAuthentication.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) { }

        public DbSet<AspnetUser> AspnetUsers { get; set; }
        public DbSet<AspnetMembership> AspnetMemberships { get; set; }
        public DbSet<AspnetRole> AspnetRoles { get; set; }
        public DbSet<AspnetUsersInRole> AspnetUsersInRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<AspnetUser>()
                .HasOne(u => u.Membership)
                .WithOne(m => m.User)
                .HasForeignKey<AspnetMembership>(m => m.UserId);

            modelBuilder.Entity<AspnetUsersInRole>()
                .HasKey(ur => new { ur.UserId, ur.RoleId });

            modelBuilder.Entity<AspnetUsersInRole>()
                .HasOne(ur => ur.User)
                .WithMany(u => u.UsersInRoles)
                .HasForeignKey(ur => ur.UserId);

            modelBuilder.Entity<AspnetUsersInRole>()
                .HasOne(ur => ur.Role)
                .WithMany(r => r.UsersInRoles)
                .HasForeignKey(ur => ur.RoleId);
        }


    }
}
