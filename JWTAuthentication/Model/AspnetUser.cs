using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace JWTAuthentication.Models
{
    [Table("aspnet_Users")]
    public class AspnetUser
    {
        [Key]
        public Guid UserId { get; set; }

        public string UserName { get; set; }

        // Navigation property to membership
        public virtual AspnetMembership Membership { get; set; }
        public virtual ICollection<AspnetUsersInRole> UsersInRoles { get; set; }
    }

    [Table("aspnet_Membership")]
    public class AspnetMembership
    {
        [Key]
        public Guid UserId { get; set; }  // PK and FK to aspnet_Users.UserId

        public string Password { get; set; }

        public string PasswordSalt { get; set; }

        public int PasswordFormat { get; set; }

        public DateTime CreateDate { get; set; }

        public DateTime LastPasswordChangedDate { get; set; }

        // Add other fields as needed

        // Navigation property back to User
        public virtual AspnetUser User { get; set; }
    }

    [Table("aspnet_Roles")]
    public class AspnetRole
    {
        [Key]
        public Guid RoleId { get; set; }

        public string RoleName { get; set; }

        public string LoweredRoleName { get; set; }

        public virtual ICollection<AspnetUsersInRole> UsersInRoles { get; set; }
    }

    [Table("aspnet_UsersInRoles")]
    public class AspnetUsersInRole
    {
        [Key, Column(Order = 0)]
        public Guid UserId { get; set; }

        [Key, Column(Order = 1)]
        public Guid RoleId { get; set; }

        [ForeignKey("UserId")]
        public virtual AspnetUser User { get; set; }

        [ForeignKey("RoleId")]
        public virtual AspnetRole Role { get; set; }
    }

}
