defmodule OAuth2Utils do
  @moduledoc """
  Util functions for OAuth2 and connected (OpenID Connect, UMA2) standards

  Standard sets are the following:
  * `:oauth2`: refers to RFC6749 and all other RFCs published by the IETF
  * `:oidc`: refers to OpenID Connect ([https://openid.net/developers/specs/](speifications))
  * `:uma2`: refers to User Managed Access specifications published by Kantara initiative
  Note that regarding origin of values, IETF have precedence over the others.
  """

  @access_token_types %{
    "Bearer" => [standard_set: :oauth2]
  }
  @authorization_endpoint_response_types %{
    "code" => [standard_set: :oauth2],
    "code id_token" => [standard_set: :oidc],
    "code id_token token" => [standard_set: :oidc],
    "code token" => [standard_set: :oidc],
    "id_token" => [standard_set: :oidc],
    "id_token token" => [standard_set: :oidc],
    "none" => [standard_set: :oidc],
    "token" => [standard_set: :oauth2]
  }
  @extension_errors %{
    "invalid_request" => [standard_set: :oauth2],
    "invalid_token" => [standard_set: :oauth2],
    "insufficient_scope" => [standard_set: :oauth2],
    "unsupported_token_type" => [standard_set: :oauth2],
    "interaction_required" => [standard_set: :oidc],
    "login_required" => [standard_set: :oidc],
    "session_selection_required" => [standard_set: :oidc],
    "consent_required" => [standard_set: :oidc],
    "invalid_request_uri" => [standard_set: :oidc],
    "invalid_request_object" => [standard_set: :oidc],
    "request_not_supported" => [standard_set: :oidc],
    "request_uri_not_supported" => [standard_set: :oidc],
    "registration_not_supported" => [standard_set: :oidc],
    "need_info" => [standard_set: :uma2],
    "request_denied" => [standard_set: :uma2],
    "request_submitted" => [standard_set: :uma2]
  }
  @parameters %{
    "client_id" => [standard_set: :oauth2, locations: [:authorization_request, :token_request]],
    "client_secret" => [standard_set: :oauth2, locations: [:token_request]],
    "response_type" => [standard_set: :oauth2, locations: [:authorization_request]],
    "redirect_uri" => [standard_set: :oauth2, locations: [:authorization_request, :token_request]],
    "scope" => [standard_set: :oauth2, locations: [:authorization_request, :authorization_response, :token_request, :token_response]],
    "state" => [standard_set: :oauth2, locations: [:authorization_request, :authorization_response]],
    "code" => [standard_set: :oauth2, locations: [:authorization_response, :token_request]],
    "error" => [standard_set: :oauth2, locations: [:authorization_response, :token_response]],
    "error_description" => [standard_set: :oauth2, locations: [:authorization_response, :token_response]],
    "error_uri" => [standard_set: :oauth2, locations: [:authorization_response, :token_response]],
    "grant_type" => [standard_set: :oauth2, locations: [:token_request]],
    "access_token" => [standard_set: :oauth2, locations: [:authorization_response, :token_response]],
    "token_type" => [standard_set: :oauth2, locations: [:authorization_response, :token_response]],
    "expires_in" => [standard_set: :oauth2, locations: [:authorization_response, :token_response]],
    "username" => [standard_set: :oauth2, locations: [:token_request]],
    "password" => [standard_set: :oauth2, locations: [:token_request]],
    "refresh_token" => [standard_set: :oauth2, locations: [:token_request, :token_response]],
    "nonce" => [standard_set: :oidc, locations: [:authorization_request]],
    "display" => [standard_set: :oidc, locations: [:authorization_request]],
    "prompt" => [standard_set: :oidc, locations: [:authorization_request]],
    "max_age" => [standard_set: :oidc, locations: [:authorization_request]],
    "ui_locales" => [standard_set: :oidc, locations: [:authorization_request]],
    "claims_locales" => [standard_set: :oidc, locations: [:authorization_request]],
    "id_token_hint" => [standard_set: :oidc, locations: [:authorization_request]],
    "login_hint" => [standard_set: :oidc, locations: [:authorization_request]],
    "acr_values" => [standard_set: :oidc, locations: [:authorization_request]],
    "claims" => [standard_set: :oidc, locations: [:authorization_request]],
    "registration" => [standard_set: :oidc, locations: [:authorization_request]],
    "request" => [standard_set: :oidc, locations: [:authorization_request]],
    "request_uri" => [standard_set: :oidc, locations: [:authorization_request]],
    "id_token" => [standard_set: :oidc, locations: [:authorization_response, :access_token_response]],
    "session_state" => [standard_set: :oidc, locations: [:authorization_response, :access_token_response]],
    "assertion" => [standard_set: :oidc, locations: [:token_request]],
    "client_assertion" => [standard_set: :oauth2, locations: [:token_request]],
    "client_assertion_type" => [standard_set: :oauth2, locations: [:token_request]],
    "code_verifier" => [standard_set: :oauth2, locations: [:token_request]],
    "code_challenge" => [standard_set: :oauth2, locations: [:authorization_request]],
    "code_challenge_method" => [standard_set: :oauth2, locations: [:authorization_request]],
    "claim_token" => [standard_set: :uma2, locations: [:client_request, :token_endpoint]],
    "pct" => [standard_set: :uma2, locations: [:client_request, :token_endpoint, :authorization_server_response, :token_endpoint]],
    "rpt" => [standard_set: :uma2, locations: [:client_request, :token_endpoint]],
    "ticket" => [standard_set: :uma2, locations: [:client_request, :token_endpoint]],
    "upgraded" => [standard_set: :uma2, locations: [:authorization_server_response, :token_endpoint]],
    "vtr" => [standard_set: :oauth2, locations: [:authorization_request, :token_request]]
  }
  @token_type_hints %{
    "access_token" => [standard_set: :oauth2],
    "refresh_token" => [standard_set: :oauth2],
    "pct" => [standard_set: :uma2]
  }
  @uris %{
    "urn:ietf:params:oauth:grant-type:jwt-bearer" => [standard_set: :oauth2],
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" => [standard_set: :oauth2],
    "urn:ietf:params:oauth:grant-type:saml2-bearer" => [standard_set: :oauth2],
    "urn:ietf:params:oauth:client-assertion-type:saml2-bearer" => [standard_set: :oauth2],
    "urn:ietf:params:oauth:token-type:jwt" => [standard_set: :oauth2]
  }
  @dynamic_client_registration_metadata %{
    "redirect_uris" => [standard_set: :oauth2],
    "token_endpoint_auth_method" => [standard_set: :oauth2],
    "grant_types" => [standard_set: :oauth2],
    "response_types" => [standard_set: :oauth2],
    "client_name" => [standard_set: :oauth2],
    "client_uri" => [standard_set: :oauth2],
    "logo_uri" => [standard_set: :oauth2],
    "scope" => [standard_set: :oauth2],
    "contacts" => [standard_set: :oauth2],
    "tos_uri" => [standard_set: :oauth2],
    "policy_uri" => [standard_set: :oauth2],
    "jwks_uri" => [standard_set: :oauth2],
    "jwks" => [standard_set: :oauth2],
    "software_id" => [standard_set: :oauth2],
    "software_version" => [standard_set: :oauth2],
    "client_id" => [standard_set: :oauth2],
    "client_secret" => [standard_set: :oauth2],
    "client_id_issued_at" => [standard_set: :oauth2],
    "client_secret_expires_at" => [standard_set: :oauth2],
    "registration_access_token" => [standard_set: :oauth2],
    "registration_client_uri" => [standard_set: :oauth2],
    "application_type" => [standard_set: :oidc],
    "sector_identifier_uri" => [standard_set: :oidc],
    "subject_type" => [standard_set: :oidc],
    "id_token_signed_response_alg" => [standard_set: :oidc],
    "id_token_encrypted_response_alg" => [standard_set: :oidc],
    "id_token_encrypted_response_enc" => [standard_set: :oidc],
    "userinfo_signed_response_alg" => [standard_set: :oidc],
    "userinfo_encrypted_response_alg" => [standard_set: :oidc],
    "userinfo_encrypted_response_enc" => [standard_set: :oidc],
    "request_object_signing_alg" => [standard_set: :oidc],
    "request_object_encryption_alg" => [standard_set: :oidc],
    "request_object_encryption_enc" => [standard_set: :oidc],
    "token_endpoint_auth_signing_alg" => [standard_set: :oidc],
    "default_max_age" => [standard_set: :oidc],
    "require_auth_time" => [standard_set: :oidc],
    "default_acr_values" => [standard_set: :oidc],
    "initiate_login_uri" => [standard_set: :oidc],
    "request_uris" => [standard_set: :oidc],
    "claims_redirect_uris" => [standard_set: :uma2]
  }
  @token_endpoint_authentication_methods %{
    "none" => [standard_set: :oauth2],
    "client_secret_post" => [standard_set: :oauth2],
    "client_secret_basic" => [standard_set: :oauth2],
    "client_secret_jwt" => [standard_set: :oidc],
    "private_key_jwt" => [standard_set: :oidc]
  }
  @pkce_code_challenge_methods %{
    "plain" => [standard_set: :oauth2],
    "S256" => [standard_set: :oauth2]
  }
  @token_introspection_response_members %{
    "active" => [standard_set: :oauth2],
    "username" => [standard_set: :oauth2],
    "client_id" => [standard_set: :oauth2],
    "scope" => [standard_set: :oauth2],
    "token_type" => [standard_set: :oauth2],
    "exp" => [standard_set: :oauth2],
    "iat" => [standard_set: :oauth2],
    "nbf" => [standard_set: :oauth2],
    "sub" => [standard_set: :oauth2],
    "aud" => [standard_set: :oauth2],
    "iss" => [standard_set: :oauth2],
    "jti" => [standard_set: :oauth2],
    "permissions" => [standard_set: :uma2],
    "vot" => [standard_set: :oauth2],
    "vtm" => [standard_set: :oauth2],
  }
  @authorization_server_metadata %{
    "issuer" => [standard_set: :oauth2],
    "authorization_endpoint" => [standard_set: :oauth2],
    "token_endpoint" => [standard_set: :oauth2],
    "jwks_uri" => [standard_set: :oauth2],
    "registration_endpoint" => [standard_set: :oauth2],
    "scopes_supported" => [standard_set: :oauth2],
    "response_types_supported" => [standard_set: :oauth2],
    "response_modes_supported" => [standard_set: :oauth2],
    "grant_types_supported" => [standard_set: :oauth2],
    "token_endpoint_auth_methods_supported" => [standard_set: :oauth2],
    "token_endpoint_auth_signing_alg_values_supported" => [standard_set: :oauth2],
    "service_documentation" => [standard_set: :oauth2],
    "ui_locales_supported" => [standard_set: :oauth2],
    "op_policy_uri" => [standard_set: :oauth2],
    "op_tos_uri" => [standard_set: :oauth2],
    "revocation_endpoint" => [standard_set: :oauth2],
    "revocation_endpoint_auth_methods_supported" => [standard_set: :oauth2],
    "revocation_endpoint_auth_signing_alg_values_supported" => [standard_set: :oauth2],
    "introspection_endpoint" => [standard_set: :oauth2],
    "introspection_endpoint_auth_methods_supported" => [standard_set: :oauth2],
    "introspection_endpoint_auth_signing_alg_values_supported" => [standard_set: :oauth2],
    "code_challenge_methods_supported" => [standard_set: :oauth2],
    "signed_metadata" => [standard_set: :oauth2],
    "userinfo_endpoint" => [standard_set: :oidc],
    "acr_values_supported" => [standard_set: :oidc],
    "subject_types_supported" => [standard_set: :oidc],
    "id_token_signing_alg_values_supported" => [standard_set: :oidc],
    "id_token_encryption_alg_values_supported" => [standard_set: :oidc],
    "id_token_encryption_enc_values_supported" => [standard_set: :oidc],
    "userinfo_signing_alg_values_supported" => [standard_set: :oidc],
    "userinfo_encryption_alg_values_supported" => [standard_set: :oidc],
    "userinfo_encryption_enc_values_supported" => [standard_set: :oidc],
    "request_object_signing_alg_values_supported" => [standard_set: :oidc],
    "request_object_encryption_alg_values_supported" => [standard_set: :oidc],
    "request_object_encryption_enc_values_supported" => [standard_set: :oidc],
    "display_values_supported" => [standard_set: :oidc],
    "claim_types_supported" => [standard_set: :oidc],
    "claims_supported" => [standard_set: :oidc],
    "claims_locales_supported" => [standard_set: :oidc],
    "claims_parameter_supported" => [standard_set: :oidc],
    "request_parameter_supported" => [standard_set: :oidc],
    "request_uri_parameter_supported" => [standard_set: :oidc],
    "require_request_uri_registration" => [standard_set: :oidc]
  }
  @grant_types %{
    "authorization_code" => [standard_set: :oauth2, uses_authorization_endpoint: true],
    "implicit" => [standard_set: :oauth2, uses_authorization_endpoint: true],
    "password" => [standard_set: :oauth2, uses_authorization_endpoint: false],
    "client_credentials" => [standard_set: :oauth2, uses_authorization_endpoint: false],
    "refresh_token" => [standard_set: :oauth2, uses_authorization_endpoint: false],
    "urn:ietf:params:oauth:grant-type:jwt-bearer" => [standard_set: :oauth2, uses_authorization_endpoint: false],
    "urn:ietf:params:oauth:grant-type:saml2-bearer" => [standard_set: :oauth2, uses_authorization_endpoint: false]
  }

  @type standard_set :: :oauth2 | :oidc | :uma2
  @type standard_sets :: [standard_set]
  @type access_token_type :: String.t
  @type authorization_endpoint_response_type :: String.t
  @type extension_error :: String.t
  @type parameter :: String.t
  @type parameter_location :: :authorization_request | :authorization_response | :token_request | :token_response | :access_token_response | :client_request | :authorization_server_response
  @type token_type_hint :: String.t
  @type uri :: String.t
  @type dynamic_client_registration_metadata :: String.t
  @type token_endpoint_authentication_method :: String.t
  @type pkce_code_challenge_method :: String.t
  @type token_introspection_response_member :: String.t
  @type authorization_server_metadata :: String.t
  @type grant_type :: String.t
  @type client_id :: String.t
  @type client_secret :: String.t

  @doc """
  Returns the access token types as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-types)

  ## Example
  ```elixir
   iex> OAuth2Utils.get_access_token_types()
   ["Bearer"]
  ```
  """

  @spec get_access_token_types(standard_sets) :: [access_token_type]
  def get_access_token_types(standard_sets \\ [:oauth2]) do
    @access_token_types
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the authorization endpoint response types as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#endpoint)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_authorization_endpoint_response_types([:oauth2, :oidc])
    ["code", "code id_token", "code id_token token", "code token", "id_token",
     "id_token token", "none", "token"]
  ```
  """

  @spec get_authorization_endpoint_response_types(standard_sets) :: [authorization_endpoint_response_type]
  def get_authorization_endpoint_response_types(standard_sets \\ [:oauth2]) do
    @authorization_endpoint_response_types
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the extension errors as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_extension_errors([:oidc])
    ["consent_required", "interaction_required", "invalid_request_object",
     "invalid_request_uri", "login_required", "registration_not_supported",
     "request_not_supported", "request_uri_not_supported",
     "session_selection_required"]
  ```
  """

  @spec get_extension_errors(standard_sets) :: [extension_error]
  def get_extension_errors(standard_sets \\ [:oauth2]) do
    @extension_errors
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the oauth parameters as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#parameters)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_parameters([:uma2])
    ["rpt", "pct", "claim_token", "upgraded", "ticket"]
  ```
  """

  @spec get_parameters(standard_sets) :: [parameter]
  def get_parameters(standard_sets \\ [:oauth2]) do
    @parameters
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the oauth parameters for a location. The locations are the following:
  * `:authorization_request`, `:authorization_response`, `:token_request` and `:token_response` from the OAuth2 specification
  * `:access_token_response` specific value from the OpenID Connect specification
  * `:client_request` and `:authorization_server_response` specific values from UMA 2.0 specification

  ## Example
  ```elixir
    iex> OAuth2Utils.get_parameters_for_location(:authorization_response, [:oauth2, :oidc])
    ["error_uri", "error", "error_description", "token_type", "access_token",
     "state", "scope", "expires_in", "code", "session_state", "id_token"]
  ```
  """

  @spec get_parameters_for_location(parameter_location, standard_sets) :: [parameter]
  def get_parameters_for_location(location, standard_sets \\ [:oauth2]) do
    @parameters
    |> Enum.filter(fn {_, v} -> location in Keyword.get(v, :locations) and Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the token type hints as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-type-hint)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_token_type_hints()
    ["access_token", "refresh_token"]
  ```
  """

  @spec get_token_type_hints(standard_sets) :: [token_type_hint]
  def get_token_type_hints(standard_sets \\ [:oauth2]) do
    @token_type_hints
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the OAuth2 URIs as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#uri)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_uris()
    ["urn:ietf:params:oauth:grant-type:jwt-bearer",
     "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
     "urn:ietf:params:oauth:grant-type:saml2-bearer",
     "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
     "urn:ietf:params:oauth:token-type:jwt"]
  ```
  """

  @spec get_uris(standard_sets) :: [uri]
  def get_uris(standard_sets \\ [:oauth2]) do
    @uris
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns dynamic client registration metadata as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#client-metadata)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_dynamic_client_registration_metadata([:oidc])
    ["default_max_age", "require_auth_time", "userinfo_signed_response_alg",
     "userinfo_encrypted_response_enc", "token_endpoint_auth_signing_alg",
     "request_object_encryption_alg", "request_uris",
     "id_token_signed_response_alg", "request_object_encryption_enc",
     "userinfo_encrypted_response_alg", "sector_identifier_uri", "application_type",
     "id_token_encrypted_response_alg", "default_acr_values", "subject_type",
     "initiate_login_uri", "request_object_signing_alg",
     "id_token_encrypted_response_enc"]
  ```
  """

  @spec get_dynamic_client_registration_metadata(standard_sets) :: [dynamic_client_registration_metadata]
  def get_dynamic_client_registration_metadata(standard_sets \\ [:oauth2]) do
    @dynamic_client_registration_metadata
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the token endpoint authentication methods as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_token_endpoint_authentication_methods()
    ["client_secret_basic", "client_secret_post", "none"]
    iex> OAuth2Utils.get_token_endpoint_authentication_methods([:oauth2, :oidc])
    ["client_secret_basic", "client_secret_jwt", "client_secret_post", "none",
     "private_key_jwt"]
  ```
  """

  @spec get_token_endpoint_authentication_methods(standard_sets) :: [token_endpoint_authentication_method]
  def get_token_endpoint_authentication_methods(standard_sets \\ [:oauth2]) do
    @token_endpoint_authentication_methods
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the PKCE code challenge methods as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#pkce-code-challenge-method)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_pkce_code_challenge_methods()
    ["S256", "plain"]
  ```
  """

  @spec get_pkce_code_challenge_methods(standard_sets) :: [pkce_code_challenge_method]
  def get_pkce_code_challenge_methods(standard_sets \\ [:oauth2]) do
    @pkce_code_challenge_methods
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the token introspection response members as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-introspection-response)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_token_introspection_response_members([:uma2])
    ["permissions"]
  ```
  """

  @spec get_token_introspection_response_members(standard_sets) :: [token_introspection_response_member]
  def get_token_introspection_response_members(standard_sets \\ [:oauth2]) do
    @token_introspection_response_members
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the authorization server metadata as documented in the [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#authorization-server-metadata)
  and in the [Open ID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) specification

  ## Example
  ```elixir
    iex> OAuth2Utils.get_authorization_server_metadata([:oidc])
    ["require_request_uri_registration", "claims_parameter_supported",
     "subject_types_supported", "id_token_encryption_enc_values_supported",
     "request_object_encryption_enc_values_supported",
     "userinfo_signing_alg_values_supported", "display_values_supported",
     "userinfo_encryption_enc_values_supported", "request_uri_parameter_supported",
     "request_object_signing_alg_values_supported", "claim_types_supported",
     "request_object_encryption_alg_values_supported", "userinfo_endpoint",
     "id_token_encryption_alg_values_supported", "claims_locales_supported",
     "request_parameter_supported", "userinfo_encryption_alg_values_supported",
     "acr_values_supported", "claims_supported",
     "id_token_signing_alg_values_supported"]
  ```
  """

  @spec get_authorization_server_metadata(standard_sets) :: [authorization_server_metadata]
  def get_authorization_server_metadata(standard_sets \\ [:oauth2]) do
    @authorization_server_metadata
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns the grant types as documented in ["OAuth 2.0 Dynamic Client Registration Protocol [RFC7591]"](https://tools.ietf.org/html/rfc7591)

  ## Example
  ```elixir
    iex> OAuth2Utils.get_authorization_server_metadata([:oidc])
    iex> OAuth2Utils.get_grant_types()
    ["authorization_code", "client_credentials", "implicit", "password",
     "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer",
     "urn:ietf:params:oauth:grant-type:saml2-bearer"]
  ```
  """

  @spec get_grant_types(standard_sets) :: [grant_type]
  def get_grant_types(standard_sets \\ [:oauth2]) do
    @grant_types
    |> Enum.filter(fn {_, v} -> Keyword.get(v, :standard_set) in standard_sets end)
    |> Enum.unzip()
    |> elem(0)
  end

  @doc """
  Returns `true` if the grant type requires the use of the authorization endpoint, `false` otherwise

  ## Example
  ```elixir
    iex> OAuth2Utils.uses_authorization_endpoint?("implicit")
    true
    iex> OAuth2Utils.uses_authorization_endpoint?("client_credentials")
    false
    iex> OAuth2Utils.uses_authorization_endpoint?("password")
    false
  ```
  """

  @spec uses_authorization_endpoint?(grant_type) :: boolean()
  def uses_authorization_endpoint?(grant_type), do: @grant_types[grant_type][:uses_authorization_endpoint] == true

  @vschar "\\x20-\\x7E"
  #@nqchar "\\x21\\x23-\\x5B\\x5D-\\x7E"
  #@nqschar "\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E"
  @unicodecharnocrlf "\\x09\\x20-\\x7E\\x80-\\x{D7FF}\\x{E000}-\\x{FFFD}\\x{10000}-\\x{10FFFF}"

  @doc """
  Returns `true` if the parameter is a valid client_id, `false` otherwise

  ## Example
  ```elixir
  iex> OAuth2Utils.valid_client_id_param?("my_client_23")
  true
  iex> OAuth2Utils.valid_client_id_param?("my_client¯23")
  false
  ```
  """

  @spec valid_client_id_param?(client_id) :: boolean()
  def valid_client_id_param?(client_id) do
    Regex.run(~r{^[#{@vschar}]*$}, client_id) != nil
  end

  @doc """
  Returns `true` if the parameter is a valid client secret, `false` otherwise
  """

  @spec valid_client_secret_param?(client_secret) :: boolean()
  def valid_client_secret_param?(client_secret) do
    Regex.run(~r{^[#{@vschar}]*$}, client_secret) != nil
  end
  @doc """
  Returns `true` is the authorization code parameter is valid, `false` otherwise

  ## Example
  ```elixir
  iex> OAuth2Utils.valid_authorization_code_param?("WIrgzqwBTQrgx*^TcyhBXonuCQ;',oi2~QO")
  true
  iex> OAuth2Utils.valid_authorization_code_param?("Hï")
  false
  ```
  """

  @spec valid_authorization_code_param?(String.t()) :: boolean
  def valid_authorization_code_param?(authorization_code) do
    Regex.run(~r{^[#{@vschar}]+$}, authorization_code) != nil
  end

  @doc """
  Returns `true` is the access token parameter is valid, `false` otherwise

  ## Example
  ```elixir
  iex> OAuth2Utils.valid_access_token_param?("2YotnFZFEjr1zCsicMWpAA")
  true
  iex> OAuth2Utils.valid_access_token_param?("2YоtnFZFEjr1zCsicMWpАA")
  false
  ```
  """

  @spec valid_access_token_param?(String.t()) :: boolean
  def valid_access_token_param?(access_token) do
    Regex.run(~r{^[#{@vschar}]+$}, access_token) != nil
  end

  @doc """
  Returns `true` is the refresh token parameter is valid, `false` otherwise

  ## Example
  ```elixir
  iex> OAuth2Utils.valid_refresh_token_param?("tGzv3JOkF0XG5Qx2TlKWIA")
  true
  iex> OAuth2Utils.valid_refresh_token_param?("tGzv3J\x13OkF0XG5Qx2TlKWIA")
  false
  ```
  """

  @spec valid_refresh_token_param?(String.t()) :: boolean
  def valid_refresh_token_param?(refresh_token) do
    Regex.run(~r{^[#{@vschar}]+$}, refresh_token) != nil
  end

  @doc """
  Returns `true` is the parameter is a valid RFC6749 username parameter,
  `false` otherwise

  ```elixir
  iex> OAuth2Utils.valid_username_param?("молду")
  true
  iex> OAuth2Utils.valid_username_param?("john\nsmith")
  false
  ```
  """

  @spec valid_username_param?(String.t()) :: boolean
  def valid_username_param?(username) do
    Regex.run(~r{^[#{@unicodecharnocrlf}]*$}iu, username) != nil
  end

  @doc """
  Returns `true` is the parameter is a valid RFC6749 password parameter,
  `false` otherwise
  """

  @spec valid_password_param?(String.t()) :: boolean
  def valid_password_param?(password) do
    Regex.run(~r{^[#{@unicodecharnocrlf}]*$}iu, password) != nil
  end
end
