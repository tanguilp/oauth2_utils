defmodule OAuth2UtilsTest do
  use ExUnit.Case
  import OAuth2Utils.Scope

  test "OAuth2 scopes" do
    assert  oauth2_scope?("abc")
    assert  oauth2_scope?("abc:def")
    assert  oauth2_scope?("{~~~~~}")

    refute oauth2_scope?("a b c")
    refute oauth2_scope?("a\\c")
    refute oauth2_scope?("abc\x05def")
  end
end
