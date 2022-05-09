using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityProvider.Domain;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens.Saml2;
using Saml2Constants = ITfoxtec.Identity.Saml2.Schemas.Saml2Constants;

namespace IdentityProvider.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Settings settings;
        private readonly Saml2Configuration config;

        public AuthController(IOptions<Settings> settingsAccessor, IOptions<Saml2Configuration> samlConfiguration)
        {
            settings = settingsAccessor.Value;
            config = samlConfiguration.Value;
        }

        [Route("Login")]
        [HttpGet]
        public IActionResult Login()
        {
            if (Request.Query.ContainsKey(ITfoxtec.Identity.Saml2.Schemas.Saml2Constants.Message.SamlRequest))
            {
                var requestBinding = new Saml2RedirectBinding();
                var relyingParty = ValidateRelyingParty(ReadRelyingPartyFromLoginRequest(requestBinding));
                var saml2AuthnRequest = new Saml2AuthnRequest(config);
                try
                {
                    requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnRequest);

                    return View(nameof(Login), new LoginModel()
                    {
                        RelyingPartyString = ReadRelyingPartyFromLoginRequest(requestBinding),
                        Email = "",
                        Password = "",
                        QueryString = Request.QueryString.Value
                    });
                }
                catch (Exception exc)
                {
#if DEBUG
                    Debug.WriteLine($"Saml 2.0 Authn Request error: {exc.ToString()}\nSaml Auth Request: '{saml2AuthnRequest.XmlDocument?.OuterXml}'\nQuery String: {Request.QueryString}");
#endif
                    return LoginResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Responder, requestBinding.RelayState, relyingParty);
                }
            }
            else
            {
                return View(nameof(Login), new LoginModel()
                {
                    RelyingPartyString = string.Empty,
                    Email = "",
                    Password = "",
                    QueryString = Request.QueryString.Value
                });
            }
        }

        [Route("Login")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(Domain.LoginModel loginModel)
        {

            try
            {
                if (loginModel.Email != "test" && loginModel.Password != "test")
                    return View(nameof(Login), loginModel);




                if (string.IsNullOrEmpty(loginModel.RelyingPartyString))
                {
                    var claimsIdentity = new ClaimsIdentity(CreateTestUserClaims("test"), Saml2Constants.AuthenticationScheme);
                    await HttpContext.SignInAsync(Saml2Constants.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity),
                        new AuthenticationProperties
                        {
                            AllowRefresh = true,
                            IsPersistent = true,
                            IssuedUtc = DateTime.UtcNow,
                            ExpiresUtc = DateTimeOffset.UtcNow.AddDays(24)
                        });
                    return RedirectToAction("Index", "Home");
                }

                var requestBinding = new Saml2RedirectBinding();
                var httpRequest = new ITfoxtec.Identity.Saml2.Http.HttpRequest
                {
                    Method = "GET",
                    QueryString = loginModel.QueryString,
                    Query = System.Web.HttpUtility.ParseQueryString(loginModel.QueryString)
                };
                var relyingParty = ValidateRelyingParty(loginModel.RelyingPartyString);
                var saml2AuthnRequest = new Saml2AuthnRequest(config);
                requestBinding.Unbind(httpRequest, saml2AuthnRequest);

                var sessionIndex = Guid.NewGuid().ToString();
                var claims = CreateTestUserClaims(saml2AuthnRequest.Subject?.NameID?.ID);

                return LoginResponse(saml2AuthnRequest.Id, Saml2StatusCodes.Success, requestBinding.RelayState, relyingParty, sessionIndex, claims);
            }
            catch (Exception exc)
            {
                return View(nameof(Login), loginModel);
            }
        }



        [HttpPost("Logout")]
        public IActionResult Logout()
        {
            var requestBinding = new Saml2PostBinding();
            var relyingParty = ValidateRelyingParty(ReadRelyingPartyFromLogoutRequest(requestBinding));

            var saml2LogoutRequest = new Saml2LogoutRequest(config);
            saml2LogoutRequest.SignatureValidationCertificates = new X509Certificate2[] { relyingParty.SignatureValidationCertificate };
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2LogoutRequest);

                // **** Delete user session ****

                return LogoutResponse(saml2LogoutRequest.Id, Saml2StatusCodes.Success, requestBinding.RelayState, saml2LogoutRequest.SessionIndex, relyingParty);
            }
            catch (Exception exc)
            {
#if DEBUG
                Debug.WriteLine($"Saml 2.0 Logout Request error: {exc.ToString()}\nSaml Logout Request: '{saml2LogoutRequest.XmlDocument?.OuterXml}'");
#endif
                return LogoutResponse(saml2LogoutRequest.Id, Saml2StatusCodes.Responder, requestBinding.RelayState, saml2LogoutRequest.SessionIndex, relyingParty);
            }
        }

        [Authorize]
        [HttpGet]
        public IActionResult IdpInitiate(string relyingPartyStr)
        {
            var response = new Saml2AuthnResponse(config);
            response.Status = Saml2StatusCodes.Success;
            var relyingParty = ValidateRelyingParty(relyingPartyStr);
            var sessionIndex = Guid.NewGuid().ToString();

            return LoginResponse(new Saml2Id(), Saml2StatusCodes.Success, string.Empty, relyingParty, sessionIndex, User.Claims);
        }

        private string ReadRelyingPartyFromLoginRequest<T>(Saml2Binding<T> binding)
        {
            return binding.ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2AuthnRequest(config))?.Issuer;
        }

        private string ReadRelyingPartyFromLogoutRequest<T>(Saml2Binding<T> binding)
        {
            return binding.ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2LogoutRequest(config))?.Issuer;
        }

        private IActionResult LoginResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, RelyingParty relyingParty, string sessionIndex = null, IEnumerable<Claim> claims = null)
        {
            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = relayState;

            var saml2AuthnResponse = new Saml2AuthnResponse(config)
            {
                InResponseTo = inResponseTo,
                Status = status,
                Destination = relyingParty.SingleSignOnDestination,
            };
            if (status == Saml2StatusCodes.Success && claims != null)
            {
                saml2AuthnResponse.SessionIndex = sessionIndex;

                var claimsIdentity = new ClaimsIdentity(claims);
                saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
                //saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single());
                saml2AuthnResponse.ClaimsIdentity = claimsIdentity;

                var token = saml2AuthnResponse.CreateSecurityToken(relyingParty.Issuer, subjectConfirmationLifetime: 5, issuedTokenLifetime: 60);
            }

            return responsebinding.Bind(saml2AuthnResponse).ToActionResult();
        }

        private IActionResult LogoutResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, string sessionIndex, RelyingParty relyingParty)
        {
            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = relayState;

            var saml2LogoutResponse = new Saml2LogoutResponse(config)
            {
                InResponseTo = inResponseTo,
                Status = status,
                Destination = relyingParty.SingleLogoutResponseDestination,
                SessionIndex = sessionIndex
            };

            return responsebinding.Bind(saml2LogoutResponse).ToActionResult();
        }

        private RelyingParty ValidateRelyingParty(string issuer)
        {
            foreach (var rp in settings.RelyingParties)
            {
                try
                {
                    if (string.IsNullOrEmpty(rp.Issuer))
                    {
                        var entityDescriptor = new EntityDescriptor();
                        entityDescriptor.ReadSPSsoDescriptorFromUrl(new Uri(rp.Metadata));
                        if (entityDescriptor.SPSsoDescriptor != null)
                        {
                            rp.Issuer = entityDescriptor.EntityId;
                            rp.SingleSignOnDestination = entityDescriptor.SPSsoDescriptor.AssertionConsumerServices.Where(a => a.IsDefault).OrderBy(a => a.Index).First().Location;
                            var singleLogoutService = entityDescriptor.SPSsoDescriptor.SingleLogoutServices.First();
                            rp.SingleLogoutResponseDestination = singleLogoutService.ResponseLocation ?? singleLogoutService.Location;
                            rp.SignatureValidationCertificate = entityDescriptor.SPSsoDescriptor.SigningCertificates.First();
                        }
                        else
                        {
                            throw new Exception($"SPSsoDescriptor not loaded from metadata '{rp.Metadata}'.");
                        }
                    }
                }
                catch (Exception exc)
                {
                    //log error
#if DEBUG
                    Debug.WriteLine($"SPSsoDescriptor error: {exc.ToString()}");
#endif
                }
            }

            return settings.RelyingParties.Where(rp => rp.Issuer != null && rp.Issuer.Equals(issuer, StringComparison.InvariantCultureIgnoreCase)).Single();
        }

        private IEnumerable<Claim> CreateTestUserClaims(string selectedNameID)
        {
            var userId = selectedNameID ?? "12345";
            yield return new Claim(ClaimTypes.NameIdentifier, userId);
            yield return new Claim(ClaimTypes.Upn, $"{userId}@email.test");
            yield return new Claim(ClaimTypes.Email, $"{userId}@someemail.test");
        }
    }
}
