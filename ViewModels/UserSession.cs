using System.ComponentModel.DataAnnotations;

namespace _233531N_Ace_Job_Agency.ViewModels
{
    public class UserSession
    {
        [Key] // Marks this as the primary key
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public string SessionToken { get; set; }
    }
}
