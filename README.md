# OAuth2Utils

Util functions for OAuth2 and connected (OpenID Connect, UMA2) standards

Standard sets are the following:
* `:oauth2`: refers to RFC6749 and all other RFCs published by the IETF
* `:oidc`: refers to OpenID Connect ([https://openid.net/developers/specs/](speifications))
* `:uma2`: refers to User Managed Access specifications published by Kantara initiative
Note that regarding origin of values, IETF have precedence over the others.

## Installation

```elixir
def deps do
  [
    {:oauth2_utils, "~> 0.1.0"}
  ]
end
