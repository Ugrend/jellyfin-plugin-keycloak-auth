using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;
using JWT.Builder;
using MediaBrowser.Common;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace Jellyfin.Plugin.Keycloak
{
    public class KeyCloakAuthenticationProviderPlugin : IAuthenticationProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<KeyCloakAuthenticationProviderPlugin> _logger;
        private readonly IApplicationHost _applicationHost;
        private  IUserManager _userManager;
        private String TwoFactorPattern = @"(.*)_2FA=(.*)$";

        private bool CreateUser => Plugin.Instance.Configuration.CreateUser;
        private String AuthServerUrl => Plugin.Instance.Configuration.AuthServerUrl;
        private String Realm => Plugin.Instance.Configuration.Realm;
        private String Resource => Plugin.Instance.Configuration.Resource;
        private String ClientSecret => Plugin.Instance.Configuration.ClientSecret;
        private bool Enable2FA => Plugin.Instance.Configuration.Enable2FA;

        private HttpClient GetHttpClient()
        {
            return _httpClientFactory.CreateClient(NamedClient.Default);
        }

        private String TokenURI => $"{AuthServerUrl}/realms/{Realm}/protocol/openid-connect/token";

        private async Task<KeycloakUser> GetKeycloakUser(string username, string password, string totp)
        {
            var httpClient = GetHttpClient();
            var keyValues = new List<KeyValuePair<string, string>>();
            keyValues.Add( new KeyValuePair<string, string>("username", username));
            keyValues.Add( new KeyValuePair<string, string>("password", password));
            keyValues.Add( new KeyValuePair<string, string>("grant_type", "password"));
            keyValues.Add( new KeyValuePair<string, string>("client_id", Resource));
            if (!String.IsNullOrWhiteSpace(ClientSecret))
            {
                keyValues.Add(new KeyValuePair<string, string>("client_secret", ClientSecret));
            }

            if (!String.IsNullOrWhiteSpace(totp))
            {
                keyValues.Add(new KeyValuePair<string, string>("totp", totp));
            }

            var content = new FormUrlEncodedContent(keyValues);
            var response = await httpClient.PostAsync(TokenURI, content).ConfigureAwait(false);
            var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            var parsed = await JsonSerializer.DeserializeAsync<KeycloakTokenResponse>(responseStream).ConfigureAwait(false);
            if (parsed == null)
                return null;
            try
            {
                var jwtToken = JwtBuilder.Create().Decode<IDictionary<string, object>>(parsed.access_token);
                List<string> perms = new List<string>();
                try
                {
                    var resourceAccess = (JObject)jwtToken["resource_access"];
                    perms = ((JArray)(((JObject)resourceAccess[Resource])["roles"])).ToObject<List<string>>();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Could not parse permissions for resource {Resource}");
                }

                return new KeycloakUser {Username = username, Permissions = perms};
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing jwt token");
            }

            return null;
        }

        private async Task<User> UpdateUserInfo(KeycloakUser keycloakUser, User jellyfinUser)
        {
            jellyfinUser.SetPermission(PermissionKind.IsDisabled, true);
            jellyfinUser.SetPermission(PermissionKind.IsAdministrator, false);
            jellyfinUser.SetPermission(PermissionKind.EnableContentDownloading, false);
            foreach (string permission in keycloakUser.Permissions)
            {
                switch (permission)
                {
                    case "administrator":
                        jellyfinUser.SetPermission(PermissionKind.IsAdministrator, true);
                        break;
                    case "allowed_access":
                        jellyfinUser.SetPermission(PermissionKind.IsDisabled, false);
                        break;
                }
            }
            await _userManager.UpdateUserAsync(jellyfinUser).ConfigureAwait(false);
            return jellyfinUser;
        }

        public async Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            _userManager ??= _applicationHost.Resolve<IUserManager>();
            string totp = null;
            if (Enable2FA)
            {
                var match = Regex.Match(password, TwoFactorPattern);
                if (match.Success)
                {
                    password = match.Groups[1].Value;
                    totp = match.Groups[2].Value;
                }
            }
            User user = null;
            try
            {
                user = _userManager.GetUserByName(username);
            }
            catch (Exception e)
            {
                _logger.LogWarning("User Manager could not find a user for Keycloak User, this may not be fatal", e);
            }

            KeycloakUser keycloakUser = await GetKeycloakUser(username, password, totp);
            if (keycloakUser == null)
            {
                throw new AuthenticationException("Error completing Keycloak login. Invalid username or password.");
            }

            if (user == null)
            {
                if (CreateUser)
                {
                    _logger.LogInformation($"Creating user {username}");
                    user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
                    user.AuthenticationProviderId = GetType().FullName;
                    await UpdateUserInfo(keycloakUser, user);
                }
                else
                {
                    _logger.LogError("Keycloak User not configured for Jellyfin: {username}", username);
                    throw new AuthenticationException(
                        $"Automatic User Creation is disabled and there is no Jellyfin user for authorized Uid: {username}");
                }

            }
            else
            {
                await UpdateUserInfo(keycloakUser, user);
            }
            if (user.HasPermission(PermissionKind.IsDisabled))
            {
                // If the user no longer has permission to access revoke all sessions for this user
                _logger.LogInformation($"{username} is disabled, revoking all sessions");
                var sessionHandler = _applicationHost.Resolve<ISessionManager>();
                sessionHandler.RevokeUserTokens(user.Id, null);
            }
            return new ProviderAuthenticationResult { Username = username};
        }

        public bool HasPassword(User user)
        {
            return true;
        }

        public Task ChangePassword(User user, string newPassword)
        {
            throw new System.NotImplementedException();
        }
        public KeyCloakAuthenticationProviderPlugin(IHttpClientFactory httpClientFactory,
            IApplicationHost applicationHost,
            ILogger<KeyCloakAuthenticationProviderPlugin> logger)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _applicationHost = applicationHost;
        }

        public string Name => "Keycloak-Authentication";
        public bool IsEnabled => true;
    }
}
