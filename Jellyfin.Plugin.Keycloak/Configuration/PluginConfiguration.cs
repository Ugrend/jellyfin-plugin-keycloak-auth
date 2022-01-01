using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.Keycloak.Configuration;

/// <summary>
/// The main plugin.
/// </summary>
public class PluginConfiguration : BasePluginConfiguration
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PluginConfiguration"/> class.
    /// </summary>
    public PluginConfiguration()
    {
        // set default options here
        this.CreateUser = true;
        this.Enable2Fa = false;
        this.AuthServerUrl = string.Empty;
        this.Realm = string.Empty;
        this.Resource = string.Empty;
        this.ClientSecret = string.Empty;
    }

    /// <summary>
    /// Gets or sets a value indicating whether an user from keycloak exists Jellyfin.
    /// </summary>
    public bool CreateUser { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an user from keycloak exists Jellyfin.
    /// </summary>
    public bool Enable2Fa { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an user from keycloak exists Jellyfin.
    /// </summary>
    public string AuthServerUrl { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an user from keycloak exists Jellyfin.
    /// </summary>
    public string Realm { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an user from keycloak exists Jellyfin.
    /// </summary>
    public string Resource { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an user from keycloak exists Jellyfin.
    /// </summary>
    public string ClientSecret { get; set; }
}
