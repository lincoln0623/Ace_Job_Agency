using _233531N_Ace_Job_Agency.Model;
using _233531N_Ace_Job_Agency.Services;
using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace _233531N_Ace_Job_Agency.Middleware
{
    public class SessionTimeoutMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionTimeoutMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IUserSessionService sessionService, UserManager<User> userManager, SignInManager<User> signInManager, AppDbContext dbContext)
        {
            Console.WriteLine("[DEBUG] Middleware invoked");

            if (context.User.Identity.IsAuthenticated)
            {
                Console.WriteLine("[DEBUG] User is authenticated");

                var user = await userManager.GetUserAsync(context.User);
                if (user != null)
                {
                    Console.WriteLine($"[DEBUG] User found: {user.Id}");

                    var lastActivity = context.Session.GetString("LastActivity");
                    var currentTime = DateTime.UtcNow;

                    Console.WriteLine($"[DEBUG] Current Time: {currentTime}");
                    Console.WriteLine($"[DEBUG] LastActivity in session: {lastActivity}");

                    if (!string.IsNullOrEmpty(lastActivity))
                    {
                        var lastActivityTime = DateTime.Parse(lastActivity);
                        var sessionTimeout = TimeSpan.FromMinutes(10);

                        Console.WriteLine($"[DEBUG] Last Activity Time: {lastActivityTime}");
                        Console.WriteLine($"[DEBUG] Timeout Threshold: {sessionTimeout.TotalMinutes} minutes");

                        if (currentTime - lastActivityTime > sessionTimeout)
                        {
                            Console.WriteLine($"[DEBUG] Session timeout triggered for user: {user.Id}");

                            // Remove session from the database
                            await sessionService.DeleteSessionTokenAsync(user.Id);
                            Console.WriteLine($"[DEBUG] Session token removed from database for user: {user.Id}");

                            // Log timeout in audit logs
                            dbContext.AuditLogs.Add(new AuditLog
                            {
                                UserId = user.Id,
                                Action = "User session timed out",
                                Timestamp = DateTime.UtcNow
                            });

                            // Sign out user
                            await signInManager.SignOutAsync();
                            Console.WriteLine($"[DEBUG] User signed out: {user.Id}");

                            await dbContext.SaveChangesAsync();

                            // Clear session and redirect to login
                            context.Session.Clear();
                            context.Response.Redirect("/Login");
                            Console.WriteLine("[DEBUG] Redirecting to /Login due to session timeout");

                            return; // Stop further request processing
                        }
                        else
                        {
                            Console.WriteLine($"[DEBUG] User session is still active");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[DEBUG] No LastActivity found in session, setting it now.");
                    }

                    // Update last activity timestamp
                    context.Session.SetString("LastActivity", DateTime.UtcNow.ToString());
                    Console.WriteLine("[DEBUG] Updated LastActivity timestamp in session");
                }
                else
                {
                    Console.WriteLine("[DEBUG] User not found in database");
                }
            }
            else
            {
                Console.WriteLine("[DEBUG] User is not authenticated, skipping session timeout check");
            }

            await _next(context);
        }
    }
}
