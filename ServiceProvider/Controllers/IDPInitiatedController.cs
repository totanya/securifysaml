﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Util;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace ServiceProvider.Controllers
{
    [AllowAnonymous]
    [Route("IdPInitiated")]
    public class IdPInitiatedController : Controller
    {
        private readonly Saml2Configuration config;

        public IdPInitiatedController(IOptions<Saml2Configuration> configAccessor)
        {
            this.config = configAccessor.Value;
        }

        public IActionResult Initiate()
        {
            //var serviceProviderRealm = "https://some-domain.com/some-service-provider";

            //var binding = new Saml2PostBinding();
            //binding.RelayState = $"RPID={Uri.EscapeDataString(serviceProviderRealm)}";

            //var config = new Saml2Configuration();

            //conf ig.Issuer = "http://some-domain.com/this-application";
            //config.SingleSignOnDestination = new Uri("https://test-adfs.itfoxtec.com/adfs/ls/");
            //config.SigningCertificate = config.SigningCertificate;
            //config.SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature;

            //var appliesToAddress = "https://test-adfs.itfoxtec.com/adfs/services/trust";

            //var response = new Saml2AuthnResponse(config);
            //response.Status = Saml2StatusCodes.Success;

            //var claimsIdentity = new ClaimsIdentity(CreateClaims());
            //response.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
            //response.ClaimsIdentity = claimsIdentity;
            //var token = response.CreateSecurityToken(appliesToAd dress);

            //return binding.Bind(response).ToActionResult();


            var serviceProviderRealm = "https://localhost:44359";

            var binding = new Saml2PostBinding();
            binding.RelayState = $"RPID={Uri.EscapeDataString(serviceProviderRealm)}";

            var config = new Saml2Configuration();

            config.Issuer = "https://localhost:44359";
            
            config.SingleSignOnDestination = new Uri("https://localhost:44305/auth/login");
            config.SigningCertificate = config.SigningCertificate;
            config.SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature;

            var appliesToAddress = "https://test-adfs.itfoxtec.com/adfs/services/trust";

            var response = new Saml2AuthnResponse(config);
            response.Status = Saml2StatusCodes.Success;

            var claimsIdentity = new ClaimsIdentity(CreateClaims());
            response.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
            response.ClaimsIdentity = claimsIdentity;
            var token = response.CreateSecurityToken(appliesToAddress);

            return binding.Bind(response).ToActionResult();

        }

        private IEnumerable<Claim> CreateClaims()
        {
            yield return new Claim(ClaimTypes.NameIdentifier, "some-user-identity");
            yield return new Claim(ClaimTypes.Email, "some-user@domain.com");
        }
    }
}
