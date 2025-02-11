using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace _233531N_Ace_Job_Agency.Model
{
	public class AppDbContext : IdentityDbContext<User>
    {
		private readonly IConfiguration _configuration;

		// Update constructor to accept IConfiguration
		public AppDbContext(DbContextOptions<AppDbContext> options, IConfiguration configuration)
			: base(options)
		{
			_configuration = configuration;
		}

		public DbSet<User> Users { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
		public DbSet<AuditLog> AuditLogs { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
		{
			// Only configure if options are not already set.
			if (!optionsBuilder.IsConfigured)
			{
				string connectionString = _configuration.GetConnectionString("AppConnectionString");
				optionsBuilder.UseSqlServer(connectionString);
			}
		}
	}
}