
# NTFA (New Traefik Forward Auth)
NTFA is a minimal forward auth service for traefik.

Starting to enhance my homelab with auth I found thomseddon/traefik-forward-auth. At that point in time, the last commit was 3 years ago. IMHO unacceptable for something security related. Out of the over 300 forks jordemort/traefik-forward-auth stood out with 35 stars. But also his repo had the last commit a year ago. From the 13 forks of that repo, traPitech/traefik-forward-auth stood out with 3 stars. This repo looked to be promising as it had documentation about what has been merged and modified. I could have called it a day here, but decided to take a dive in the code. 

After a few weeks of tinkering around, this is my version of Traefik Forward Auth. It is not copy-paste backwards compatible,
but it should be fairly easy for you to migrate.

NOTE: This is still a fork, NOT a whole from zero rewrite. Sadly github doesnt allow forking from yourself.

## Changes
- Updated to Go 1.22.1
- Updated all libraries
- Removed the traefik dependency by removing the rules feature. More on that down below
- Removed different auth modes. No more allow or soft-auth.
- Changed to use net/http everywhere
- Changed logging from logrus to log/slog
- Added support for env files
- Removed google as hard coded provider, its just a matter of configuration
- Refactored the project into different namespaces
- Improved whitelists
- Added more examples
- Added more documentation
- Added support for docker secrets

### What did not change
- The auth logic
- The oauth and oidc providers

## Releases
// TODO

## Is this repo maintained? and contributing
I will try to do my best to keep everything up to date.

## Migration Guide
See examples or help.txt. Most of the logic stayed the same, but some names changed.

### Migrating when using Kubernetes
Sadly I have no clue about kubernetes. If you know more about it, feel free to contribute examples or fixes for kubernetes.

### Migrating when using rules
I didnt like the use of traefik lib inside a traefik middleware. It felt unnecessarily repeated.
With the binary/container having around 10MB in size it should be feasible to have multiple instances running if neccessary.
See rules example in examples.

## Documentation
See examples and help.txt. 
This is only what I think worthy of spending some more words on.

### How to provide configuration
- Command line flags
- Ini config file
- Environment Variables
- Env file

Avoid declaring the same configuration variable multiple times in different places, this can lead to unpredictable behaviour.

#### As flags
Some options such as for example "cookie domains" repesent a list.
When providing via flags it can be declare multiple times `--cookie.domains=abc.com --cookie.domains=def.com`,
or comma separated `--cookie.domains=abc.com,def.com`.

#### Env Variable/File
In help.txt you can see each parameters env var name, e.g. "[$COOKIE_DOMAINS]"
Env vars cannot be set multiple times, always use comma separated here.

You can specify an env file via `-e /path/to/your/.env-file`.
You can do that multiple times, e.g. `-e /path/to/your/client-id -e ./.client-secret`.
This is also the work around to use docker secrets. See examples/docker-secrets for more info about that.

#### Ini config
I'm not really sure about here. I recommend using env file. I just kept the feature.

### Auth Host
When set, when a user returns from authentication with a 3rd party provider they will always be forwarded to this host. By using one central host, this means you only need to add this `auth-host` as a valid redirect uri to your 3rd party provider.

The host should be specified without protocol or path, for example: `--auth-host="auth.example.com"`

For more details, please also read the [Auth Host Mode](#auth-host-mode), operation mode in the concepts section.

Please Note - this should be considered advanced usage, if you are having problems please try disabling this option and then re-read the [Auth Host Mode](#auth-host-mode) section.


### Header names
User header names, can be set multiple times, ONLY comma separated as ENV (default: X-Forwarded-User) [$HEADER_NAMES].

The authenticated user is set in the this header. 
Make sure to add this name to the `authResponseHeaders` config option in traefik.


### Url Path
Customise the path that this service uses to handle the callback following authentication.

Default: `/auth`

Please note that when using the default [Overlay Mode](#overlay-mode) requests to this exact path will be intercepted by this service and not forwarded to your application. Use this option (or [Auth Host Mode](#auth-host-mode)) if the default `/auth` path will collide with an existing route in your application.

### Secret
Used to sign cookies authentication, should be a random (e.g. `openssl rand -hex 32`)

### User id path
Dot notation path of a UserID for use with whitelist and X-Forwarded-User (default: email) [$USER_ID_PATH]
// TODO more about dot notation

### Cookie Settings
#### Domains
When set, if a user successfully completes authentication, then if the host of the original request requiring authentication is a subdomain of a given cookie domain, then the authentication cookie will be set for the higher level cookie domain. This means that a cookie can allow access to multiple subdomains without re-authentication. Can be specificed multiple times.

For example:
```
--cookie.domains="example.com"  --cookie.domains="test.org"
```

For example, if the cookie domain `test.com` has been set, and a request comes in on `app1.test.com`, following authentication the auth cookie will be set for the whole `test.com` domain. As such, if another request is forwarded for authentication from `app2.test.com`, the original cookie will be sent and so the request will be allowed without further authentication.

Beware however, if using cookie domains whilst running multiple instances of traefik/traefik-forward-auth for the same domain, the cookies will clash. You can fix this by using a different `cookie.name` in each host/cluster or by using the same `secret` in both instances.

#### Insecure
If you are not using HTTPS between the client and traefik, you will need to pass the `insecure-cookie` option which will mean the `Secure` attribute on the cookie will not be set. See examples/secure-cookie

#### Lifetime
How long a successful authentication session should last. See https://pkg.go.dev/time#ParseDuration for valid values.


### Whitelist
You can restrict who can login with the following parameters:
* `whitelist.domains` - Use this to limit logins to a specific domain, e.g. test.com only
* `whitelist.users` - Use this to only allow specific users to login e.g. thom@test.com only
* `whitelist.networks`

Note, if you pass both `whitelist` and `domain`, then the default behaviour is for only `whitelist` to be used and `domain` will be effectively ignored. You can allow users matching *either* `whitelist` or `domain` by passing the `match-whitelist-or-domain` parameter.

#### Networks
This option adds an IP address or an IP network given in CIDR notation to the list of whitelisted networks. Requests originating from a trusted network are considered authenticated and are never redirected to an Identity Provider. The option can be used multiple times or comma separated.
* `--whitelist.networks=2.3.4.5` adds a single IP (`2.3.4.5`) as a trusted IP.
* `--whitelist.networks=30.1.0.0/16` adds the address range from `30.1.0.1` to `30.1.255.254` as a trusted range
* `--whitelist.networks=1.2.3.4,5.6.7.8,9.10.11.12/13`

Note! You might need a traefik real ip plugin or so!
// TODO Investigate

### OIDC and Oauth
Prefer OIDC, use Oauth when OIDC is not supported.
Note, OIDC is a superset of Oauth.

#### Scopes
Any scopes that should be included in the request (default: profile, email)

#### Prompt
Most of the times not neccessary to manually configure. E.g. "select_account".


### Oauth
#### Token style
How token is presented when querying the User URL. Can be `header` or `query`, defaults to `header`. With `header` the token is provided in an Authorization header, with query the token is provided in the `access_token` query string value.



## Operation Modes

### Overlay Mode

Overlay is the default operation mode, in this mode the authorisation endpoint is overlaid onto any domain. By default the `/_oauth` path is used, this can be customised using the `url-path` option.

The user flow will be:

1. Request to `www.myapp.com/home`
2. User redirected to Google login
3. After Google login, user is redirected to `www.myapp.com/_oauth`
4. Token, user and CSRF cookie is validated (this request in intercepted and is never passed to your application)
5. User is redirected to `www.myapp.com/home`
6. Request is allowed

As the hostname in the `redirect_uri` is dynamically generated based on the original request, every hostname must be permitted in the Google OAuth console (e.g. `www.myappp.com` would need to be added in the above example)

### Auth Host Mode

This is an optional mode of operation that is useful when dealing with a large number of subdomains, it is activated by using the `auth-host` config option (see [this example docker-compose.yml](examples/traefik-v2/swarm/docker-compose-auth-host.yml) or [this kubernetes example](https://github.com/thomseddon/traefik-forward-auth/tree/master/examples/traefik-v2/kubernetes/advanced-separate-pod)).

For example, if you have a few applications: `app1.test.com`, `app2.test.com`, `appN.test.com`, adding every domain to Google's console can become laborious.
To utilise an auth host, permit domain level cookies by setting the cookie domain to `test.com` then set the `auth-host` to: `auth.test.com`.

The user flow will then be:

1. Request to `app10.test.com/home/page`
2. User redirected to Google login
3. After Google login, user is redirected to `auth.test.com/_oauth`
4. Token, user and CSRF cookie is validated, auth cookie is set to `test.com`
5. User is redirected to `app10.test.com/home/page`
6. Request is allowed

With this setup, only `auth.test.com` must be permitted in the Google console.

Two criteria must be met for an `auth-host` to be used:

1. Request matches given `cookie-domain`
2. `auth-host` is also subdomain of same `cookie-domain`

Please note: For Auth Host mode to work, you must ensure that requests to your auth-host are routed to the traefik-forward-auth container, as demonstrated with the service labels in the [docker-compose-auth.yml](examples/traefik-v2/swarm/docker-compose-auth-host.yml) example and the [ingressroute resource](examples/traefik-v2/kubernetes/advanced-separate-pod/traefik-forward-auth/ingress.yaml) in a kubernetes example.

### Logging in

The service provides an endpoint to allow users to explicitly login.
You can set `redirect` query parameter to redirect on login (defaults to `/`).

### Logging Out

The service provides an endpoint to clear a users session and "log them out". 
The path is created by appending `/logout` to your configured `path` and so with the default settings it will be: `/auth/logout`.

You can set `redirect` query parameter to redirect on logout (defaults to `/`).
Note that the user will not have a valid auth cookie after being logged out.

Note: This only clears the auth cookie from the users browser and as this service is stateless, it does not invalidate the cookie against future use. 
So if the cookie was recorded, for example, it could continue to be used for the duration of the cookie lifetime.

## Copyright

2018 Thom Seddon

## License

[MIT](LICENSE.md)
