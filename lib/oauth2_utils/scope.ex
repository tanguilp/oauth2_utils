defmodule OAuth2Utils.Scope do
  @moduledoc """
  Util functions to work with OAuth2 scopes
  """

  @typedoc """
  Scope token as defined in [RFC6749 section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3)
  """
  @type scope :: String.t

  @type scope_set :: MapSet.t(scope)

  @doc """
  Checks if the param is a valid OAuth2 scope

  ## Example
  ```elixir
  iex> OAuth2Utils.Scope.oauth2_scope?("document.read")
  true
  iex> OAuth2Utils.Scope.oauth2_scope?("invalid\\scope")
  false
  ```
  """

  @spec oauth2_scope?(String.t) :: boolean()
  def oauth2_scope?(val) do
    Regex.run(~r{^[\x21\x23-\x5B\x5D-\x7E]+$}, val) != nil
  end
end
