using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.Keycloak.Configuration
{

    public class PluginConfiguration : BasePluginConfiguration
    {
        public bool CreateUser { get; set; }
        public bool Enable2FA { get; set; }
        public string AuthServerUrl { get; set; }
        public string Realm { get; set; }
        public string Resource { get; set; }
        public string ClientSecret { get; set; }


        public PluginConfiguration()
        {
            // set default options here
            CreateUser = true;
            Enable2FA = false;
            AuthServerUrl = "";
            Realm = "";
            Resource = "";
            ClientSecret = "";
        }
    }
}
