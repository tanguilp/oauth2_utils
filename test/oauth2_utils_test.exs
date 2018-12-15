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

  test "valid_client_id_param regex" do
    assert OAuth2Utils.valid_client_id_param?("  &$@($9023 ewfqkamzql<,fqh.o UIGYTDTUFKWL")
    assert OAuth2Utils.valid_client_id_param?("")

    refute OAuth2Utils.valid_client_id_param?("\x16dasxgrsbhd")
    refute OAuth2Utils.valid_client_id_param?("zareeasr<zgw\x9axezfregqzw")
  end
end
