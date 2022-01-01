using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Jellyfin.Plugin.Keycloak
{
    /// <summary>
    /// Response model for the keycloak token.
    /// </summary>
    [DataContract]
    public class KeycloakTokenResponse
    {
        /// <summary>
        /// Gets or sets the access token instance.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the expiry time instance.
        /// </summary>
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        /// <summary>
        /// Gets or sets the not-before-policy instance.
        /// </summary>
        [JsonPropertyName("not-before-policy")]
        public int NotBeforePolicy { get; set; }

        /// <summary>
        /// Gets or sets the refresh token instance.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the scope instance.
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// Gets or sets the session state instance.
        /// </summary>
        [JsonPropertyName("session_state")]
        public string? SessionState { get; set; }

        /// <summary>
        /// Gets or sets the token type instance.
        /// </summary>
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
    }
}
