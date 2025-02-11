using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace _233531N_Ace_Job_Agency.Pages
{
    [IgnoreAntiforgeryToken] // Avoid infinite redirect loops
    public class AntiForgeryModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}
