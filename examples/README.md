# Examples
See basic.docker-compose.yml.

The examples assumes:
- You own example.com
- A test service like whoami.example.com
- You have https setup in traefik
- NTFA being accessible via auth.example.com
- NTFA url-path set to "/auth" (default)

## Providers

### Keycloak (selfhosted)
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
### Gitea (selfhosted)
### Microsoft
### Apple