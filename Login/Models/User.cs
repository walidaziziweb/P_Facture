using Swashbuckle.AspNetCore.Swagger;
using System;
using System.ComponentModel.DataAnnotations;

namespace Login.Models
{
    public class User
    {
        [Key]
        public int Id { get;set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Username { get; set; }
        public string Token { get; set; }
        public string Role { get; set; }

        public DateTime CreatedAt { get; set; }
        public DateTime UpdatetedAt { get; set; }

    }
}
