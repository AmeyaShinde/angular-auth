using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;

        public UserController(AppDbContext context)
        {
            _context = context;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }

            var user = await _context.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName && x.Password == userObj.Password);
            if (user == null)
            {
                return NotFound(new { Message = "User Not Found!" });
            }

            return Ok(new { Message = "Login Success!" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";

            await _context.Users.AddAsync(userObj);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "User Registered!" });
        }
    }
}
