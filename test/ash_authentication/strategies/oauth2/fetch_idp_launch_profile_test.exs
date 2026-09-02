# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.FetchIdpLaunchProfileTest do
  @moduledoc false
  # async: false — drives a real Assent.Strategy.OAuth2.callback/3 round-trip
  # via a real Assent.HTTPAdapter (StubHTTPAdapter), wired in through the
  # global :ash_authentication, :http_adapter application env. Stubbing the
  # strategy module instead would hide exactly the kind of bug this test
  # exists to catch.
  use DataCase, async: false
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

  setup do
    original = Application.get_env(:ash_authentication, :http_adapter)
    Application.put_env(:ash_authentication, :http_adapter, StubHTTPAdapter)

    on_exit(fn ->
      if original do
        Application.put_env(:ash_authentication, :http_adapter, original)
      else
        Application.delete_env(:ash_authentication, :http_adapter)
      end
    end)

    :ok
  end

  test "reads the launch profile via a real token+userinfo exchange — no session, no `state` param — against a stock OAuth2 strategy" do
    {:ok, strategy} = Info.strategy(Example.User, :oauth2)

    StubHTTPAdapter.stub("https://example.com/oauth/token", %Assent.HTTPAdapter.HTTPResponse{
      status: 200,
      body: %{"access_token" => "at-123", "token_type" => "Bearer"}
    })

    StubHTTPAdapter.stub("https://example.com/userinfo", %Assent.HTTPAdapter.HTTPResponse{
      status: 200,
      body: %{"sub" => "person-123", "email" => "teacher@school.example"}
    })

    conn =
      :get
      |> conn("/user/oauth2/callback")
      |> Map.put(:params, %{"code" => "abc"})

    assert {:ok, %{user: user, token: token}} = Plug.fetch_idp_launch_profile(strategy, conn)
    assert user["sub"] == "person-123"
    assert token["access_token"] == "at-123"
  end

  test "a spent/invalid code fails the exchange without crashing" do
    {:ok, strategy} = Info.strategy(Example.User, :oauth2)

    StubHTTPAdapter.stub("https://example.com/oauth/token", %Assent.HTTPAdapter.HTTPResponse{
      status: 400,
      body: %{"error" => "invalid_grant"}
    })

    conn =
      :get
      |> conn("/user/oauth2/callback")
      |> Map.put(:params, %{"code" => "spent"})

    assert {:error, _reason} = Plug.fetch_idp_launch_profile(strategy, conn)
  end
end
