# Examples
See basic.docker-compose.yml.

The examples assumes:
- You own example.com
- A test service like whoami.example.com
- You have https setup in traefik
- NTFA being accessible via auth.example.com
- NTFA url-path set to "/auth" (default)

## Redirect URIs
When you setup any auth provider, the provider should ask for valid/authorised "Redirect URIs". 
You should enter all the hosts you will allow authentication from, appended with the url-path (e.g. https://app.example.com/_oauth).

By default, when not using Auth Host Mode, this will be every host in your setup (e.g. https://app1.example.com/_oauth, https://app2.example.com/_oauth)
If you are using Auth Host Mode, this will just be your auth-host (e.g. https://auth.example.com/_oauth)

## Providers

### Keycloak (selfhosted)

### Gitea (selfhosted)

### Google

See the screenshots in examples/google if you need more guidance.

`PROVIDERS_OIDC_ISSUER_URL=https://accounts.google.com`

1. Go to https://console.cloud.google.com/ and create a new project. 
2. Search for "API & Services".
3. Fill out "OAuth Consent Screen"
   1. I chose external, because I did not setup an organization.
   2. Add example.com to Authorized Domains and click "Save and Continue".
   3. As scopes choose email and profile.
   4. Add your test users
4. Go to Credentials and Create Credentials "OAuth Client ID"
   1. Application Type "Web application""
   2. Add Authorized Redirect URIs: 
      1. If using Auth-Host (recommended) "https://auth.example.com"
      2. If not using Auth-Host "https://whoami.example.com"
      3. // TODO validate non-auth-host
   3. Copy Client ID and Client Secret to a save place


### Github
You only need to register an "OAuth Application" (as opposed to a full "Github Application"), which you can do here: https://github.com/settings/applications/new

Add your redirect URIs under "User authorization callback URL".

```sh
PROVIDERS_OAUTH_AUTH_URL=https://github.com/login/oauth/authorize
PROVIDERS_OAUTH_TOKEN_URL=https://github.com/login/oauth/access_token
PROVIDERS_OAUTH_USER_URL=https://api.github.com/user
```

Note: as per [Github's documentation](https://developer.github.com/v3/users/#get-a-user), their `/user` endpoint only returns the user's email if it's publicly visible. As such, you will not be able to use the User Restriction features with the Github provider, unless all your users have their email addresses public.



### Microsoft
You should obtain your client credentials by registering an app in the Azure Portal [App Registrations](https://go.microsoft.com/fwlink/?linkid=2083908), 
full details of this process can be found [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)

When registering the app, use the correct redirect URIs as per the details in Redirect URIs above.

Once registered, head to "Manage" > "Certificates & secrets" and then create a new "Client secret" for this application.

* `PROVIDERS_OIDC_ISSUER_URL` - https://login.microsoftonline.com/{tenant}/v2.0, where {tenant} is your tenant id, shown as "Directory (tenant) ID" on your app homepage
* `PROVIDERS_OIDC_CLIENT_ID` - "Application (client) ID" on app homepage
* `PROVIDERS_OIDC_CLIENT_SECRET` - Created above
### Apple