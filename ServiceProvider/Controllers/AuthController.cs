using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ServiceProvider.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public AuthController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)
            {
                //ForceAuthn = true,
                Subject = new Subject { NameID = new NameID { ID = "abcd" } },
                NameIdPolicy = new NameIdPolicy { AllowCreate = true, Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" },
                //Extensions = new AppExtensions(),
                //RequestedAuthnContext = new RequestedAuthnContext
                //{
                //    Comparison = AuthnContextComparisonTypes.Exact,
                //    AuthnContextClassRef = new string[] { AuthnContextClassTypes.PasswordProtectedTransport.OriginalString },
                //},
            }).ToActionResult();
        }

        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);
            return binding.Bind(saml2LogoutRequest).ToActionResult();
        }

        [Route("LoggedOut")]
        public IActionResult LoggedOut()
        {
            var binding = new Saml2PostBinding();
            binding.Unbind(Request.ToGenericHttpRequest(), new Saml2LogoutResponse(config));

            return Redirect(Url.Content("~/"));
        }

        [Route("SingleLogout")]
        public async Task<IActionResult> SingleLogout()
        {
            Saml2StatusCodes status;
            var requestBinding = new Saml2PostBinding();
            var logoutRequest = new Saml2LogoutRequest(config, User);
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), logoutRequest);
                status = Saml2StatusCodes.Success;
                await logoutRequest.DeleteSession(HttpContext);
            }
            catch (Exception exc)
            {
                // log exception
                Debug.WriteLine("SingleLogout error: " + exc.ToString());
                status = Saml2StatusCodes.RequestDenied;
            }

            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = requestBinding.RelayState;
            var saml2LogoutResponse = new Saml2LogoutResponse(config)
            {
                InResponseToAsString = logoutRequest.IdAsString,
                Status = status,
            };
            return responsebinding.Bind(saml2LogoutResponse).ToActionResult();
        }
    }


    public static class ClaimsTransform
    {
        public static ClaimsPrincipal Transform(ClaimsPrincipal incomingPrincipal)
        {
            if (!incomingPrincipal.Identity.IsAuthenticated)
            {
                return incomingPrincipal;
            }

            return CreateClaimsPrincipal(incomingPrincipal);
        }

        private static ClaimsPrincipal CreateClaimsPrincipal(ClaimsPrincipal incomingPrincipal)
        {
            var claims = new List<Claim>();

            // All claims
            claims.AddRange(incomingPrincipal.Claims);

            // Or custom claims
            //claims.AddRange(GetSaml2LogoutClaims(incomingPrincipal));
            //claims.Add(new Claim(ClaimTypes.NameIdentifier, GetClaimValue(incomingPrincipal, ClaimTypes.NameIdentifier)));

            return new ClaimsPrincipal(new ClaimsIdentity(claims, incomingPrincipal.Identity.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role)
            {
                BootstrapContext = ((ClaimsIdentity)incomingPrincipal.Identity).BootstrapContext
            });
        }

        private static IEnumerable<Claim> GetSaml2LogoutClaims(ClaimsPrincipal principal)
        {
            yield return GetClaim(principal, Saml2ClaimTypes.NameId);
            yield return GetClaim(principal, Saml2ClaimTypes.NameIdFormat);
            yield return GetClaim(principal, Saml2ClaimTypes.SessionIndex);
        }

        private static Claim GetClaim(ClaimsPrincipal principal, string claimType)
        {
            return ((ClaimsIdentity)principal.Identity).Claims.Where(c => c.Type == claimType).FirstOrDefault();
        }

        private static string GetClaimValue(ClaimsPrincipal principal, string claimType)
        {
            var claim = GetClaim(principal, claimType);
            return claim != null ? claim.Value : null;
        }
    }
}
