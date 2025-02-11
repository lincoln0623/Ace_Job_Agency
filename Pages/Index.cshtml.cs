using _233531N_Ace_Job_Agency.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using System.Text;

namespace _233531N_Ace_Job_Agency.Pages
{
    [Authorize]
    [ValidateAntiForgeryToken]
    public class IndexModel : PageModel
    {
		private readonly UserManager<User> _userManager;

		[BindProperty]
		public User CurrentUser { get; set; }

		public IndexModel(UserManager<User> userManager)
		{
			_userManager = userManager;
		}

		// Encryption settings
		private static readonly string EncryptionKey = "your-256-bit-encryption-key"; // 32 bytes for AES-256
        private static readonly byte[] Iv = new byte[16]; // 16-byte IV for AES

        public async Task<IActionResult> OnGetAsync()
        {
			// If the user is not authenticated, redirect to login 
			var user = await _userManager.GetUserAsync(User);
			if (!User.Identity.IsAuthenticated || user == null)
			{
				return RedirectToPage("Login");  // Redirect if not authenticated or user is null
			}

			user.NRIC = DecryptNRIC(user.NRIC);
			CurrentUser = user;
			return Page();

		}


		// Decrypt NRIC using AES
		private string DecryptNRIC(string encryptedNric)
        {
            try
            {
                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = SHA256.HashData(Encoding.UTF8.GetBytes(EncryptionKey)); // Use your 256-bit encryption key here
                    aesAlg.IV = Iv; // 16-byte IV, same as used during encryption

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    byte[] cipherTextBytes = Convert.FromBase64String(encryptedNric);
                    byte[] plainTextBytes = decryptor.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);
                    return Encoding.UTF8.GetString(plainTextBytes);
                }
            }
            catch
            {
                return "Invalid NRIC format";
            }
        }
    }
}
