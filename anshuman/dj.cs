using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SupplierAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SupplierController : ControllerBase
    {
        private static List<Supplier> suppliers = new List<Supplier>();
        private readonly IConfiguration _config;

        public SupplierController(IConfiguration config)
        {
            _config = config;
        }

        
        [HttpPost("register")]
        public IActionResult Register([FromBody] SupplierRegisterDto request)
        {
            if (suppliers.Any(s => s.AadharCard == request.AadharCard))
                return BadRequest("Supplier already registered");

            var supplier = new Supplier
            {
                Id = Guid.NewGuid(),
                Name = request.Name,
                PhoneNumber = request.PhoneNumber,
                AadharCard = request.AadharCard,
                Username = request.Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
            };

            suppliers.Add(supplier);

            return Ok(new { message = "Supplier Registered Successfully", supplier.Username });
        }

        // LOGIN SUPPLIER
        [HttpPost("login")]
        public IActionResult Login([FromBody] SupplierLoginDto request)
        {
            var supplier = suppliers.FirstOrDefault(s => s.Username == request.Username);
            if (supplier == null || !BCrypt.Net.BCrypt.Verify(request.Password, supplier.PasswordHash))
                return Unauthorized("Invalid credentials");

            var token = GenerateJwtToken(supplier);

            return Ok(new { token });
        }

        // TEST API (Requires Authentication)
        [HttpGet("protected")]
        public IActionResult ProtectedAPI()
        {
            return Ok("You are authenticated supplier!");
        }

        // JWT Token Generator
        private string GenerateJwtToken(Supplier supplier)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, supplier.Username),
                new Claim("SupplierId", supplier.Id.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    // Supplier Entity
    public class Supplier
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string PhoneNumber { get; set; }
        public string AadharCard { get; set; }
        public string Username { get; set; }
        public string PasswordHash { get; set; }
    }

    // DTOs
    public class SupplierRegisterDto
    {
        public string Name { get; set; }
        public string PhoneNumber { get; set; }
        public string AadharCard { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class SupplierLoginDto
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
