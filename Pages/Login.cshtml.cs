using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using _233531N_Ace_Job_Agency.Services;
using Microsoft.EntityFrameworkCore;
using _233531N_Ace_Job_Agency.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace _233531N_Ace_Job_Agency.Pages
{
	[ValidateAntiForgeryToken]
	public class LoginModel : PageModel
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
					// Parse the raw JSON response using JsonDocument
					using (JsonDocument doc = JsonDocument.Parse(response))
					{
						// Safely check for properties using TryGetProperty
						if (doc.RootElement.TryGetProperty("success", out var successElement) &&
							doc.RootElement.TryGetProperty("score", out var scoreElement) &&
							doc.RootElement.TryGetProperty("action", out var actionElement))
						{
							var success = successElement.GetBoolean();
							var score = scoreElement.GetSingle();
							var action = actionElement.GetString();

							// Check the success status and score threshold
							if (success && score >= 0.5)  // You can adjust the score threshold
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

		[BindProperty]
		public Login LModel { get; set; }
		public User CurrentUser { get; set; }

		private readonly SignInManager<User> signInManager;
        private readonly IUserSessionService sessionService;
        private readonly UserManager<User> _userManager;
		private readonly AppDbContext _context;
		public LoginModel(SignInManager<User> signInManager, IUserSessionService sessionService, UserManager<User> userManager, AppDbContext context)
		{
			this.signInManager = signInManager;
			this.sessionService = sessionService;
			_userManager = userManager;
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
                //	Log reCAPTCHA failure
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = "0", // No user logged in
                    Action = "reCAPTCHA verification failed",
                    Timestamp = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();
                return Page();
            }

            // Input Sanitization
            LModel.Email = LModel.Email.Trim().ToUpperInvariant();
			LModel.Password = LModel.Password.Trim();

			// Validate email format
			if (!IsValidEmail(LModel.Email))
			{
				ModelState.AddModelError("LModel.Email", "Invalid email format.");
				return Page();
			}
            
            string normalizedEmail = LModel.Email.ToUpperInvariant();

            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedEmail);

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid login attempt.");

                // Log invalid login attempt for a non-existing user
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = "0", // User doesn't exist
                    Action = $"Failed login attempt with email: {LModel.Email}",
                    Timestamp = DateTime.UtcNow
                });

                await _context.SaveChangesAsync();
                return Page();
            }

            // Check if the user already has an active session
            var existingSessionToken = await sessionService.GetSessionTokenAsync(user.Id);

            if (!string.IsNullOrEmpty(existingSessionToken))
            {
                TempData["Message"] = "You're currently logged in on multiple devices or browsers.";

				// Log multiple session detection
				_context.AuditLogs.Add(new AuditLog
				{
					UserId = user.Id,
					Action = $"Multiple device/browser login detected for user: {user.UserName}",
					Timestamp = DateTime.UtcNow
				});

				await _context.SaveChangesAsync();
				return RedirectToPage("Index");
            }

			// Check if the user is locked out
			if (await _userManager.IsLockedOutAsync(user))
			{
				
				ModelState.AddModelError("", "Account is locked due to multiple failed login attempts. Please try again later.");

				// Log locked account attempt
				_context.AuditLogs.Add(new AuditLog
				{
					UserId = user.Id,
					Action = "Account locked due to failed logins",
					Timestamp = DateTime.UtcNow
				});

				await _context.SaveChangesAsync();
				return Page();
			} else
			{
				var failedAttempts = await _userManager.GetAccessFailedCountAsync(user);

				if (failedAttempts >= 3)
				{
					// If the user is not locked out, reset the failed attempts count
					await _userManager.ResetAccessFailedCountAsync(user);

					// Log the reset of failed attempts count
					_context.AuditLogs.Add(new AuditLog
					{
						UserId = user.Id,
						Action = "Failed attempts count reset",
						Timestamp = DateTime.UtcNow
					});

					await _context.SaveChangesAsync();
				}
			}

			// Attempt login
			var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, true);

            if (!identityResult.Succeeded)
            {
                if (identityResult.IsLockedOut)
                {
                    ModelState.AddModelError("", "Account is locked.");

                    // Log locked account attempt
                    _context.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Action = "Account locked due to failed logins",
                        Timestamp = DateTime.UtcNow
                    });
				}
                else
                {
                    ModelState.AddModelError("", "Username or Password is incorrect.");

					// Log failed login attempt
					_context.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Action = "Failed login attempt",
                        Timestamp = DateTime.UtcNow
                    });

					// Lock the account after 3 failed attempts
					var failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
					if (failedAttempts >= 3)
					{
						// Lock the account for 1 minute initially (change to 15 minutes after testing)
						await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(1));

						ModelState.Clear();
						ModelState.AddModelError("", "Too many failed login attempts. Account is locked for 15 minutes.");

						// Log account lock
						_context.AuditLogs.Add(new AuditLog
						{
							UserId = user.Id,
							Action = "Account locked due to multiple failed login attempts",
							Timestamp = DateTime.UtcNow
						});
					}
				}

                await _context.SaveChangesAsync();
                return Page();
            }

			// Reset failed attempts on successful login
			await _userManager.ResetAccessFailedCountAsync(user);

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
                IsPersistent = LModel.RememberMe,  // Store the cookie
            };

            // Store session token in the database
            await sessionService.SaveSessionTokenAsync(user.Id, sessionToken);

            // Sign in the user with the session token
            await signInManager.SignInAsync(user, LModel.RememberMe);

            return RedirectToPage("Index");
        }
		private bool IsValidEmail(string email)
		{
			// Regex for validating email format
			var emailPattern = new Regex(@"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$");
			return emailPattern.IsMatch(email);
		}
	}
}
