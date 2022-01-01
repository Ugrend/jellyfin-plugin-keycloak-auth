using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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
    /// <summary>
    /// KeyCloak Authentication Provider Plugin.
    /// </summary>
    public class KeyCloakAuthenticationProviderPlugin : IAuthenticationProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<KeyCloakAuthenticationProviderPlugin> _logger;
        private readonly IApplicationHost _applicationHost;
        private string _twoFactorPattern = @"(.*)_2FA=(.*)$";

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyCloakAuthenticationProviderPlugin"/> class.
        /// </summary>
        /// <param name="httpClientFactory">Instance of the <see cref="IHttpClientFactory"/> interface.</param>
        /// <param name="applicationHost">Instance of the <see cref="IApplicationHost"/> interface.</param>
        /// <param name="logger">Instance of the <see cref="ILogger"/> interface.</param>
        public KeyCloakAuthenticationProviderPlugin(
            IHttpClientFactory httpClientFactory,
            IApplicationHost applicationHost,
            ILogger<KeyCloakAuthenticationProviderPlugin> logger)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _applicationHost = applicationHost;
        }

        private static bool CreateUser => Plugin.Instance.Configuration.CreateUser;

        private static string AuthServerUrl => Plugin.Instance.Configuration.AuthServerUrl;

        private static string Realm => Plugin.Instance.Configuration.Realm;

        private static string Resource => Plugin.Instance.Configuration.Resource;

        private static string ClientSecret => Plugin.Instance.Configuration.ClientSecret;

        private static bool Enable2Fa => Plugin.Instance.Configuration.Enable2Fa;

        private string TokenUri => $"{AuthServerUrl}/realms/{Realm}/protocol/openid-connect/token";

        /// <inheritdoc />
        public string Name => "Keycloak-Authentication";

        /// <inheritdoc />
        public bool IsEnabled => true;

        private HttpClient GetHttpClient()
        {
            return _httpClientFactory.CreateClient(NamedClient.Default);
        }

        private async Task<KeycloakUser?> GetKeycloakUser(string username, string password, string? totp)
        {
            var httpClient = GetHttpClient();
            var keyValues = new List<KeyValuePair<string, string?>>();
            keyValues.Add(new KeyValuePair<string, string?>("username", username));
            keyValues.Add(new KeyValuePair<string, string?>("password", password));
            keyValues.Add(new KeyValuePair<string, string?>("grant_type", "password"));
            keyValues.Add(new KeyValuePair<string, string?>("client_id", Resource));
            if (!string.IsNullOrWhiteSpace(ClientSecret))
            {
                keyValues.Add(new KeyValuePair<string, string?>("client_secret", ClientSecret));
            }

            if (!string.IsNullOrWhiteSpace(totp))
            {
                keyValues.Add(new KeyValuePair<string, string?>("totp", totp));
            }

            var content = new FormUrlEncodedContent(keyValues);
            var response = await httpClient.PostAsync(TokenUri, content).ConfigureAwait(false);
            var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            KeycloakTokenResponse? parsed = await JsonSerializer.DeserializeAsync<KeycloakTokenResponse>(responseStream).ConfigureAwait(false);
            if (parsed == null)
            {
                return null;
            }

            try
            {
                var jwtToken = JwtBuilder.Create().Decode<IDictionary<string, object>>(parsed.AccessToken);
                Collection<string> perms = new Collection<string>();
                try
                {
                    var resourceAccess = (JObject)jwtToken["resource_access"];
                    perms = ((JArray)((JObject)resourceAccess[Resource])["roles"]).ToObject<Collection<string>>();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Could not parse permissions for resource: {Resource}", Resource);
                }

                KeycloakUser user = new KeycloakUser(username);
                foreach (var perm in perms)
                {
                    user.Permissions.Add(perm);
                }

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing jwt token");
            }

            return null;
        }

        private async Task UpdateUserInfo(KeycloakUser? keycloakUser, User? jellyfinUser)
        {
            var userManager = _applicationHost.Resolve<IUserManager>();
            if (jellyfinUser != null)
            {
                jellyfinUser.SetPermission(PermissionKind.IsDisabled, true);
                jellyfinUser.SetPermission(PermissionKind.IsAdministrator, false);
                jellyfinUser.SetPermission(PermissionKind.EnableContentDownloading, false);
                if (keycloakUser != null)
                {
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
                }

                await userManager.UpdateUserAsync(jellyfinUser).ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public async Task<ProviderAuthenticationResult> Authenticate(string username, string password)
        {
            var userManager = _applicationHost.Resolve<IUserManager>();
            string? totp = null;
            if (Enable2Fa)
            {
                var match = Regex.Match(password, _twoFactorPattern);
                if (match.Success)
                {
                    password = match.Groups[1].Value;
                    totp = match.Groups[2].Value;
                }
            }

            User? user = null;
            try
            {
                user = userManager.GetUserByName(username);
            }
            catch (Exception e)
            {
                _logger.LogWarning("User Manager could not find a user for Keycloak User, this may not be fatal: {E}", e);
            }

            KeycloakUser? keycloakUser = await GetKeycloakUser(username, password, totp).ConfigureAwait(false);
            if (keycloakUser == null)
            {
                throw new AuthenticationException("Error completing Keycloak login. Invalid username or password.");
            }

            if (user == null)
            {
                if (CreateUser)
                {
                    _logger.LogInformation("Creating user: {Username}", username);
                    user = await userManager.CreateUserAsync(username).ConfigureAwait(false);
                    var userAuthenticationProviderId = GetType().FullName;
                    if (userAuthenticationProviderId != null)
                    {
                        user.AuthenticationProviderId = userAuthenticationProviderId;
                    }

                    await UpdateUserInfo(keycloakUser, user).ConfigureAwait(false);
                }
                else
                {
                    _logger.LogError("Keycloak User not configured for Jellyfin: {Username}", username);
                    throw new AuthenticationException(
                        $"Automatic User Creation is disabled and there is no Jellyfin user for authorized Uid: {username}");
                }
            }
            else
            {
                await UpdateUserInfo(keycloakUser, user).ConfigureAwait(false);
            }

            if (user != null && user.HasPermission(PermissionKind.IsDisabled))
            {
                // If the user no longer has permission to access revoke all sessions for this user
                _logger.LogInformation("{Username} is disabled, revoking all sessions", username);
                var sessionHandler = _applicationHost.Resolve<ISessionManager>();
                await sessionHandler.RevokeUserTokens(user.Id, null).ConfigureAwait(false);
            }

            return new ProviderAuthenticationResult { Username = username };
        }

        /// <inheritdoc />
        public bool HasPassword(User user)
        {
            return true;
        }

        /// <inheritdoc />
        public Task ChangePassword(User user, string newPassword)
        {
            throw new NotImplementedException();
        }
    }
}
