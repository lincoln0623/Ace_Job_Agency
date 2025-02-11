using _233531N_Ace_Job_Agency.Model;
using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace _233531N_Ace_Job_Agency.Services
{
    public class UserSessionService : IUserSessionService
    {
        private readonly AppDbContext _context;

        public UserSessionService(AppDbContext context)
        {
            _context = context;
        }

        public async Task SaveSessionTokenAsync(string userId, string sessionToken)
        {
            var userSession = await _context.UserSessions.FirstOrDefaultAsync(u => u.UserId == userId);

            if (userSession == null)
            {
                userSession = new UserSession { UserId = userId, SessionToken = sessionToken };
                _context.UserSessions.Add(userSession);
            }
            else
            {
                userSession.SessionToken = sessionToken;
            }

            await _context.SaveChangesAsync();
        }

        public async Task DeleteSessionTokenAsync(string userId)
        {
            var userSession = await _context.UserSessions.FirstOrDefaultAsync(u => u.UserId == userId);

            if (userSession != null)
            {
                _context.UserSessions.Remove(userSession);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<string> GetSessionTokenAsync(string userId)
        {
            var userSession = await _context.UserSessions.FirstOrDefaultAsync(u => u.UserId == userId);
            return userSession?.SessionToken;
        }
    }
}
