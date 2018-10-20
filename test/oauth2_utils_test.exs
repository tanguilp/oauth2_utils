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

  test "OAuth2 scope params" do
    assert  oauth2_scope_param?("a")
    assert  oauth2_scope_param?("abc def ghi")
    assert  oauth2_scope_param?("abc:def ghi:xyz")
    assert  oauth2_scope_param?("{~~~~~}")

    refute oauth2_scope_param?("a b  c")
    refute oauth2_scope_param?("")
    refute oauth2_scope_param?(" a b c")
    refute oauth2_scope_param?("a b c ")
  end
end
