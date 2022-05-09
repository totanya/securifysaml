using System;
namespace IdentityProvider.Domain
{
    public class LoginModel
    {
        public string QueryString { get; set; }
        public string RelyingPartyString { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
