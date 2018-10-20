defmodule OAuth2Utils.Scope do
  @moduledoc """
  Util functions to work with OAuth2 scopes
  """

  @typedoc """
  A single scope token as defined in [RFC6749 section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3)

  Example: `mail:read`
  """
  @type scope :: String.t

  @typedoc """
  Scope param (i.e. non-empty list of space-separated scopes) as defined in [RFC6749 section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3)
  """
  @type scope_param :: String.t

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

  @doc """
  Checks if the param is a valid OAuth2 scope param

  ## Example
  ```elixir
  iex> OAuth2Utils.Scope.oauth2_scope_param?("users:read feed:edit room:manage")
  true
  iex> OAuth2Utils.Scope.oauth2_scope_param?("users:read feed:edit  room:manage")
  false
  ```
  """

  @spec oauth2_scope_param?(scope_param) :: boolean()
  def oauth2_scope_param?(val) do
    Regex.run(~r{^[\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*$}, val) != nil
  end

  defmodule Set do
    @type t :: MapSet.t(OAuth2Utils.Scope.t)

    defdelegate delete(map_set, value), to: MapSet
    defdelegate difference(map_set1, map_set2), to: MapSet
    defdelegate disjoint?(map_set1, map_set2), to: MapSet
    defdelegate equal?(map_set1, map_set2), to: MapSet
    defdelegate intersection(map_set1, map_set2), to: MapSet
    defdelegate member?(map_set, value), to: MapSet
    defdelegate new(), to: MapSet
    defdelegate new(enumerable), to: MapSet
    defdelegate new(enumerable, transform), to: MapSet
    defdelegate put(map_set, value), to: MapSet
    defdelegate size(map_set), to: MapSet
    defdelegate subset?(map_set1, map_set2), to: MapSet
    defdelegate to_list(map_set), to: MapSet
    defdelegate union(map_set1, map_set2), to: MapSet

    @doc """
    Returns a `{:ok, scope_set}` structure from a scope param if the scope param
    is well-formed, `:error` otherwise

    ## Example
    ```elixir
    iex(5)> OAuth2Utils.Scope.Set.from_scope_param("users:read feed:edit room:manage")
    {:ok, #MapSet<["feed:edit", "room:manage", "users:read"]>}
    ```
    """

    @spec from_scope_param(OAuth2Utils.Scope.scope_param) :: t
    def from_scope_param(scope_param) do
      if OAuth2Utils.Scope.oauth2_scope_param?(scope_param) do
        {:ok, new(String.split(scope_param))}
      else
        :error
      end
    end

    @doc """
    Returns a conform scope param string from a scope set

    ## Example
    ```elixir
    iex> OAuth2Utils.Scope.Set.to_scope_param(scopes)
    "calendar.read calendar.write document.read"
    ```
    """
    
    @spec to_scope_param(t) :: OAuth2Utils.Scope.scope_param
    def to_scope_param(%MapSet{} = scope_set) do
      scope_set
      |> to_list()
      |> Enum.join(" ")
    end
  end
end
