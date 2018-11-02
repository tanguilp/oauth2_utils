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

  test "client_id regex" do
    assert OAuth2Utils.client_id?("  &$@($9023 ewfqkamzql<,fqh.o UIGYTDTUFKWL")

    refute OAuth2Utils.client_id?("\x16dasxgrsbhd")
    refute OAuth2Utils.client_id?("zareeasr<zgw\x9axezfregqzw")
  end
end
