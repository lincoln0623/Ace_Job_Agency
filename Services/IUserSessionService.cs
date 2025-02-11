namespace _233531N_Ace_Job_Agency.Services
{
    public interface IUserSessionService
    {
        Task SaveSessionTokenAsync(string userId, string sessionToken);
        Task<string> GetSessionTokenAsync(string userId);
        Task DeleteSessionTokenAsync(string userId);
    }
}
