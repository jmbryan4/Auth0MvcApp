using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Auth0MvcApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Auth0MvcApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly IHttpClientFactory _clientFactory;
        private readonly IConfiguration _config;

        public AccountController(IHttpClientFactory clientFactory, IConfiguration config)
        {
            _clientFactory = clientFactory;
            _config = config;
        }

        public async Task Login(string returnUrl = "/")
        {
            await HttpContext.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = returnUrl });
        }

        [Authorize]
        public async Task Logout()
        {
            await HttpContext.SignOutAsync("Auth0", new AuthenticationProperties
            {
                // Indicate here where Auth0 should redirect the user after a logout.
                // Note that the resulting absolute Uri must be whitelisted in the 
                // **Allowed Logout URLs** settings for the client.
                RedirectUri = Url.Action("Index", "Home")
            });
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        /// <summary>
        /// This is just a helper action to enable you to easily see all claims related to a user. It helps when debugging your
        /// application to see the in claims populated from the Auth0 ID Token
        /// </summary>
        [Authorize]
        public IActionResult Claims()
        {
            return View();
        }

        /// <summary>
        /// The User.Identity.Name property looks for a claim of a type http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name on the user object.
        /// Auth0 passes the name of the user in the name claim of the ID Token, 
        /// but this does not get automatically matched to the http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name type.
        /// </summary>
        [Authorize]
        public IActionResult Profile()
        {
            return View(new UserProfileViewModel()
            {
                Name = User.Identity.Name,
                EmailAddress = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                ProfileImage = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value
            });
        }

        [Authorize(Roles ="admin")]
        public IActionResult Admin()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> ExternalApi()
        {
            var auth0Client = _clientFactory.CreateClient();
            auth0Client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var json = JsonSerializer.Serialize(new
            {
                client_id = "eKbGojuUIR7zVUthZ2uMXkrHvosXkLhx",
                client_secret = Environment.GetEnvironmentVariable("auth0_sampleApi_client_secret"),
                audience = "https://quickstarts/api",
                grant_type = "client_credentials"
            });
            var postBodyContent = new StringContent(json, Encoding.UTF8, "application/json");
            string domain = _config["Auth0:Domain"];
            var accessTokenResponse = await auth0Client.PostAsync($"https://{domain}/oauth/token", postBodyContent);
            ApiAccessToken apiAccessToken = null;

            if (accessTokenResponse.IsSuccessStatusCode)
            {
                using var responseStream = await accessTokenResponse.Content.ReadAsStreamAsync();
                apiAccessToken = await JsonSerializer.DeserializeAsync<ApiAccessToken>(responseStream);
            }

            var client = _clientFactory.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:44318/api/private");
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("authorization", $"Bearer {apiAccessToken?.AccessToken}");

            var response = await client.SendAsync(request);
            object responseObject = "sample";

            if (response.IsSuccessStatusCode)
            {
                using var responseStream = await response.Content.ReadAsStreamAsync();
                responseObject = await JsonSerializer.DeserializeAsync<object>(responseStream);
            }

            return Json(responseObject);
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
