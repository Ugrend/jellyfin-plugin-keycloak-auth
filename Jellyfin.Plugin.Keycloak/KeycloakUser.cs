using System.Collections.ObjectModel;
using Microsoft.VisualBasic;

namespace Jellyfin.Plugin.Keycloak
{
    /// <summary>
    /// User Model for Keycloak Users.
    /// </summary>
    public class KeycloakUser
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeycloakUser"/> class.
        /// </summary>
        /// <param name="username">Instance of the username of the user.</param>
        public KeycloakUser(string username)
        {
            Username = username;
            Permissions = new Collection<string>();
        }

        /// <summary>
        /// Gets or sets the value of the username of an user.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Gets the value of permissions of an user.
        /// </summary>
        public Collection<string> Permissions { get; }
    }
}
