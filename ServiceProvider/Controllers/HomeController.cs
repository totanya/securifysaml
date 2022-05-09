using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ServiceProvider.Models;

namespace ServiceProvider.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secure()
        {
            // The NameIdentifier
            var nameIdentifier = User.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single();

            return View();
        }

        public IActionResult Error()
        {
            return View();
        }
    }

}
