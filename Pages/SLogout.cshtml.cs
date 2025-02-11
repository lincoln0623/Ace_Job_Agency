using _233531N_Ace_Job_Agency.Model;
using _233531N_Ace_Job_Agency.Services;
using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace _233531N_Ace_Job_Agency.Pages
{
	[Authorize]
	public class SLogoutModel : PageModel
	{
		private readonly SignInManager<User> signInManager;
		private readonly IUserSessionService sessionService;
		private readonly UserManager<User> userManager;
		private readonly AppDbContext _context;

		public SLogoutModel(SignInManager<User> signInManager, IUserSessionService sessionService, UserManager<User> userManager, AppDbContext context)
		{
			this.signInManager = signInManager;
			this.sessionService = sessionService;
			this.userManager = userManager;
			_context = context;
		}

		public async Task<IActionResult> OnGetAsync()
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
	}
}
