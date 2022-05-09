using System;
using System.Linq;
using System.Security.Claims;
using IdentityProvider.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace IdentityProvider.Controllers
{
    public class HomeController : Controller
    {
        private readonly Settings settings;

        public HomeController(IOptions<Settings> settingsAccessor)
        {
            this.settings = settingsAccessor.Value;
        }
        public IActionResult Index()
        {
            bool isAuthenticated = User.Identity.IsAuthenticated;
            if (isAuthenticated)
            {
                ViewBag.RelyingParties = settings.RelyingParties;
            }
            
            return View();
        }


        public IActionResult Apps()
        {
            return View();
        }
    }
}
