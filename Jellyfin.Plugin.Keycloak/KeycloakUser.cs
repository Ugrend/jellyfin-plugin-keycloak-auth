using System.Collections.Generic;

namespace Jellyfin.Plugin.Keycloak
{
    public class KeycloakUser
    {
        public string Username { get; set; }
        public List<string> Permissions { get; set; }
    }
}
