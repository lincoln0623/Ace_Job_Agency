using _233531N_Ace_Job_Agency.Model;
using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using _233531N_Ace_Job_Agency.Services;

namespace _233531N_Ace_Job_Agency.Pages
{
    [ValidateAntiForgeryToken]
    public class RegisterModel : PageModel
    {
        private async Task<bool> VerifyRecaptcha(string recaptchaToken)
        {
            using (var httpClient = new HttpClient())
            {
                var secretKey = "6LexpdAqAAAAAPuKpme6Q5IQ7ImVn8-BZEW-AyzY"; // Replace with your actual reCAPTCHA Secret Key
                var apiUrl = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={recaptchaToken}";

                var response = await httpClient.GetStringAsync(apiUrl);

                try
                {
                    using (JsonDocument doc = JsonDocument.Parse(response))
                    {
                        if (doc.RootElement.TryGetProperty("success", out var successElement) &&
                            doc.RootElement.TryGetProperty("score", out var scoreElement) &&
                            doc.RootElement.TryGetProperty("action", out var actionElement))
                        {
                            var success = successElement.GetBoolean();
                            var score = scoreElement.GetSingle();
                            var action = actionElement.GetString();

                            if (success && score >= 0.5)  // Adjust score threshold if needed
                            {
                                return true;
                            }
                            else
                            {
                                return false;
                            }
                        }
                        else
                        {
                            return false;
                        }
                    }
                }
                catch (JsonException e)
                {
                    return false;
                }
            }
        }


        private readonly UserManager<User> _userManager;
		private readonly SignInManager<User> _signInManager;
        private readonly IUserSessionService sessionService;
        private readonly AppDbContext _context;

        [BindProperty]
        public User RModel { get; set; }

        // Encryption settings
        private static readonly string EncryptionKey = "your-256-bit-encryption-key"; // 32 bytes for AES-256
        private static readonly byte[] Iv = new byte[16]; // 16-byte IV for AES

        public RegisterModel(UserManager<User> userManager, SignInManager<User> signInManager, IUserSessionService sessionService, AppDbContext context)
		{
			_userManager = userManager;
			_signInManager = signInManager;
            this.sessionService = sessionService;
            _context = context;
        }

		public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            string recaptchaResponse = Request.Form["RecaptchaResponse"];

            if (!await VerifyRecaptcha(recaptchaResponse))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                // Log reCAPTCHA failure
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = "0", // No user logged in
                    Action = "reCAPTCHA verification failed",
                    Timestamp = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();
                return Page();
            }

            // Sanitize input fields
            RModel.WhoAmI = SanitizeInput(RModel.WhoAmI);
            RModel.Email = HttpUtility.HtmlEncode(RModel.Email);

            // Validate NRIC format
            if (!IsValidNRIC(RModel.NRIC))
            {
                ModelState.AddModelError("RModel.NRIC", "Invalid NRIC format.");
                return Page();
            }

            // Encrypt NRIC before storing
            RModel.NRIC = EncryptNRIC(RModel.NRIC);

            // Validate password strength (Server-side)
            if (!IsPasswordStrong(RModel.Password))
            {
                ModelState.AddModelError("RModel.Password", "Password must be at least 12 characters with uppercase, lowercase, numbers, and special characters.");
                return Page();
            }

			// Handle Resume File Upload
			if (RModel.Resume != null)
			{
				var allowedExtensions = new[] { ".pdf", ".docx" };
				var fileExtension = Path.GetExtension(RModel.Resume.FileName).ToLower();

				if (!allowedExtensions.Contains(fileExtension))
				{
					ModelState.AddModelError("RModel.Resume", "Only .pdf and .docx files are allowed.");
					return Page();
				}

				var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "resumes");

				// Ensure the folder exists
				if (!Directory.Exists(uploadsFolder))
				{
					Directory.CreateDirectory(uploadsFolder);
				}

				var uniqueFileName = $"{Guid.NewGuid()}{fileExtension}";
				var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                // Store the resume path in the ResumePath property
                RModel.ResumePath = $"/resumes/{uniqueFileName}";

                using (var stream = new FileStream(filePath, FileMode.Create))
				{
					await RModel.Resume.CopyToAsync(stream);
				}
			}

            // Create User in Identity
            var user = new User
			{
                UserName = RModel.Email,
                Email = RModel.Email,
				FirstName = RModel.FirstName,
				LastName = RModel.LastName,
                Password = RModel.Password,
                ConfirmPassword = RModel.ConfirmPassword,
                Gender = RModel.Gender,
				NRIC = RModel.NRIC,
				DateOfBirth = RModel.DateOfBirth,
                Resume = RModel.Resume,
                ResumePath = RModel.ResumePath,
                WhoAmI = RModel.WhoAmI
			};

            var result = await _userManager.CreateAsync(user, RModel.Password);
			if (result.Succeeded)
			{
                // Log successful login
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "User successfully logged in",
                    Timestamp = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();

                // Generate a unique session token
                var sessionToken = Guid.NewGuid().ToString();

                // Store session token in the cookie
                var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim("SessionToken", sessionToken)
            };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = false  // Store the cookie
                };

                // Store session token in the database
                await sessionService.SaveSessionTokenAsync(user.Id, sessionToken);

                // Sign in the user with the session token
                await _signInManager.SignInAsync(user, false);

                return RedirectToPage("Index");
            }

			foreach (var error in result.Errors)
			{
				ModelState.AddModelError("", error.Description);
			}

			return Page();

		}

        // Sanitize input to prevent XSS but allow < and >
        private string SanitizeInput(string input)
        {
            return HttpUtility.HtmlEncode(input);
        }


        // Validate NRIC format (example format validation)
        private bool IsValidNRIC(string nric)
        {
            var regex = new Regex(@"^[STFG][0-9]{7}[A-Z]$|^[EGSF][0-9]{7}[A-Z]$");
            return regex.IsMatch(nric);
        }

        // Encrypt NRIC using AES
        private string EncryptNRIC(string nric)
        {
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = SHA256.HashData(Encoding.UTF8.GetBytes(EncryptionKey));
                aesAlg.IV = Iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                byte[] plainTextBytes = Encoding.UTF8.GetBytes(nric);
                byte[] cipherTextBytes = encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);
                return Convert.ToBase64String(cipherTextBytes);
            }
        }

        // Password Strength Validation (Server-Side)
        private static bool IsPasswordStrong(string password)
        {
            var regex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?])[A-Za-z\d@$!%*?&]{12,}$");
            return regex.IsMatch(password);
        }
    }
}
