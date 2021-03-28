# Keycloak Authentication Plugin

A simple plugin for Jellyfin to authenticate against a Keycloak instance.  
  
## Requirements
* Your keycloak client config needs to have `Direct Access Grants Enabled` enabled.
* You need to add the following roles your defined client `administrator`, `allowed_access`, `allow_media_downloads`
* Map at least `allowed_access` to the users you want to be able to access jellyfin (or map it to a group)
  

## Limitations
* This only provides a an authentication method against Keycloak, it does not handle token renewal/revoking.  
eg: If you delete/invalidate/etc a users session/account in keycloak the session will remain active in Jellyfin.  
(However  if you remove the `allowed_access` role and the user logs in again all sessions in Jellyfin are revoked.)  

* It does not provide a true 'Single Sign On' as if the user is signed into the Realm already the user will still be prompted to authenticate to Jellyfin.  
  
* It does not follow oauth2 or oidc worflow, it mearly requests a token from keycloak with the username/password provided if we get a token we mark the authentication request as successfull.

## Build/Installation
1. Have .NET SDK 5.0
2. `dotnet publish --configuration Release --output bin`
3. Make a directory called `keycloak` (or whatever you want) in your jellyfin keycloak directory  
Windows: `%localappdata%\jellyfin\plugins`  
Linux: `/var/lib/jellyfin/plugins`  
Place the built `Jellyfin.Plugin.Keycloak.dll` and `JWT.dll` in the directory and restart Jellyfin
4. Configure the plugin in the webui `Admin Dashboard -> Advanced -> Plugins`

