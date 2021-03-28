using System.Runtime.Serialization;

namespace Jellyfin.Plugin.Keycloak
{
    [DataContract]
    public class KeycloakTokenResponse
    {
        public string access_token { get; set; }
        public int expires_in { get; set; }
        [DataMember(Name = "not-before-policy")]
        public int not_before_policy { get; set; }
        public string refresh_token { get; set; }
        public string scope { get; set; }
        public string session_state { get; set; }
        public string token_type { get; set; }
    }
}
