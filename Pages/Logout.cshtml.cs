using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using _233531N_Ace_Job_Agency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using _233531N_Ace_Job_Agency.Model;

namespace _233531N_Ace_Job_Agency.Pages
{
    [Authorize]
    [ValidateAntiForgeryToken]
    public class LogoutModel : PageModel
    {
		private readonly SignInManager<User> signInManager;
        private readonly IUserSessionService sessionService;
        private readonly UserManager<User> userManager;
		private readonly AppDbContext _context;

		public LogoutModel(SignInManager<User> signInManager, IUserSessionService sessionService, UserManager<User> userManager, AppDbContext context)
        {
            this.signInManager = signInManager;
            this.sessionService = sessionService;
            this.userManager = userManager;
			_context = context;
		}
        public void OnGet() { }
		public async Task<IActionResult> OnPostLogoutAsync()
		{
            // Retrieve the currently logged-in user
            var user = await userManager.GetUserAsync(User);
            if (user != null)
            {
				// Log the logout activity in the audit logs
				_context.AuditLogs.Add(new AuditLog
				{
					UserId = user.Id,
					Action = "User logged out",
					Timestamp = DateTime.UtcNow
				});
				// Delete session token from the database
				await sessionService.DeleteSessionTokenAsync(user.Id);
            }

            HttpContext.Session.Clear();
			// Expire session cookie
			if (HttpContext.Request.Cookies.ContainsKey(".AspNetCore.Session"))
			{
				HttpContext.Response.Cookies.Delete(".AspNetCore.Session");
			}
			if (HttpContext.Request.Cookies.ContainsKey(".AspNetCore.Identity.Application"))
			{
				HttpContext.Response.Cookies.Delete(".AspNetCore.Identity.Application");
			}
			await signInManager.SignOutAsync();

			await _context.SaveChangesAsync();

			return RedirectToPage("Login");
		}
		public async Task<IActionResult> OnPostDontLogoutAsync()
		{
			return RedirectToPage("Index");
		}
	}
}
