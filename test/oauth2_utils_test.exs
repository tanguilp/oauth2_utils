defmodule OAuth2UtilsTest do
  use ExUnit.Case
  doctest OAuth2Utils

  test "greets the world" do
    assert OAuth2Utils.hello() == :world
  end
end
