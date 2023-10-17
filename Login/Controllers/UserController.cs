using Login.Context;
using Login.Helpers;
using Login.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;

namespace Login.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext  _authContext;
        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }
        // Authitcation
        
        [HttpPost("authenticate")]
        public async Task<IActionResult> authenticate ([FromBody] User userObj)
        {   
            if (userObj is null)
            {
                return BadRequest("Invalid user request");
            }
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username );

            if (user == null)
            {
                return NotFound(new {Message ="User Not Found " });
            }
            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest( new {Message= "Password incorrect" });
            }
            user.Token = CreateJwt(user);
            return Ok(new{
                Token = user.Token,
                Message = "Login success" });
        }

        // register
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest("Invalid client request");
            }

            //check Username
            if( await CheckUserNameExistAsync(userObj.Username)) 
            {
                return BadRequest(new { message="Usename is already exist" });
            }
            //check email
            if (await CheckEmailExistAsync(userObj.Email))
            {
                return BadRequest(new { message = "Email is already exist" });
            }
            //check password
            var pass = CheckPasswordStrength(userObj.Password);

            if(!string.IsNullOrEmpty(pass))
                {
                return BadRequest(new {Message = pass.ToString()  });
                }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "Admin";
            userObj.Token = "";

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User register" });
        }

        private Task<bool> CheckUserNameExistAsync(string username)
                                    => _authContext.Users.AnyAsync(x => x.Username == username );

        private Task<bool> CheckEmailExistAsync(string email)
                            => _authContext.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length < 8) 
            {
                sb.Append("Minimun password length should be 8" +Environment.NewLine);
            }
            if (!(Regex.IsMatch(password,"[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
            {
                sb.Append("Password should alphanumeric" + Environment.NewLine);
            }
            if (!(Regex.IsMatch(password, "[<,>,@,!,:,;,%,/,-,+,*,\\[,\\],{,},?,=,',&,#,£,(,),°,0,^]")))
            {
                sb.Append("Password should contain special chars" + Environment.NewLine);
            }

            return sb.ToString();

        }

        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret.........");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Role, $"{user.FirstName} {user.LastName}")
            });

            var credentiale = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(1),
                SigningCredentials = credentiale
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);

        }

        // Get All Users
        // [Authorize]
        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            var user = await _authContext.Users.ToListAsync();
            return Ok(user);
        }


    }
}