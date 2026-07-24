# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

  describe "request/2" do
    test "it builds the redirect url and redirects the user" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      assert conn =
               :get
               |> conn("/", %{})
               |> SessionPipeline.call([])
               |> Plug.request(strategy)

      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      assert String.starts_with?(location, "https://example.com/authorize?")
      session = get_session(conn, "user/oauth2")
      assert session.state =~ ~r/.+/
    end
  end

  describe "callback/2 with no session (cross-site form_post)" do
    setup do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)
      {:ok, strategy: strategy}
    end

    test "a POST with no session renders an interstitial that re-POSTs same-origin", %{
      strategy: strategy
    } do
      conn =
        :post
        |> conn("/user/oauth2/callback", %{"code" => "abc", "state" => "x<script>"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      assert conn.status == 200

      assert {"content-type", "text/html" <> _} =
               Enum.find(conn.resp_headers, &(elem(&1, 0) == "content-type"))

      body = conn.resp_body
      assert body =~ ~s(<form method="post" action="/user/oauth2/callback">)
      assert body =~ ~s(name="code" value="abc")
      # values are HTML-escaped
      assert body =~ ~s(value="x&lt;script&gt;")
      refute body =~ "x<script>"
      # the loop guard marker is added
      assert body =~ ~s(name="_ash_authentication_reflected" value="1")

      # the interstitial must NOT rewrite the session cookie, or the fresh cookie
      # would clobber the real session and the same-origin re-POST would arrive
      # without it.
      assert conn.private[:plug_session_info] == :ignore
    end

    test "an already-reflected POST with no session fails closed rather than looping", %{
      strategy: strategy
    } do
      conn =
        :post
        |> conn("/user/oauth2/callback", %{
          "code" => "abc",
          "state" => "xyz",
          "_ash_authentication_reflected" => "1"
        })
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      refute conn.status == 200
      assert conn.private[:authentication_result] == {:error, nil}
    end

    test "a GET with no session does not render an interstitial", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user/oauth2/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      refute conn.status == 200
      assert conn.private[:authentication_result] == {:error, nil}
    end
  end

  describe "callback/2 with no session (IdP-initiated)" do
    test "a stateless GET fails closed when idp_initiated_login? is disabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      conn =
        :get
        |> conn("/user/oauth2/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # No request phase ran (no stored session), and the strategy hasn't opted
      # into IdP-initiated handling, so we must not complete authentication.
      assert conn.private[:authentication_result] == {:error, nil}
      refute conn.status == 302
    end

    test "a stateless GET restarts the request phase when idp_initiated_login? is enabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # The stateless callback is treated as a trigger: discard the inbound
      # response and redirect into the request phase (OIDC Core §4), which mints
      # a fresh `state` in the session for later verification.
      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      assert String.starts_with?(location, "https://example.com/authorize?")

      session = get_session(conn, "user/oauth2_idp_initiated")
      assert session.state =~ ~r/.+/

      # We did not complete authentication from the inbound `code`.
      refute match?({:ok, _}, conn.private[:authentication_result])
    end

    test "a stateless POST still takes the interstitial, not the restart, when idp_initiated_login? is enabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)

      conn =
        :post
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # `idp_initiated_login?` restarts on GET only. A stateless POST is the
      # cross-site form_post case (Sign in with Apple), so it must render the
      # same-origin re-POST interstitial — the request-phase restart must not
      # pre-empt it.
      assert conn.status == 200
      assert conn.resp_body =~ ~s(name="_ash_authentication_reflected" value="1")
      refute conn.status == 302
    end

    test "a stateless GET carrying a `state` fails closed rather than restarting again" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc", "state" => "xyz"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # A genuine IdP-initiated launch carries no `state`. This one does, so a
      # request phase already ran and its session should have been present — it
      # could not be persisted, or was stripped. Restarting would mint another
      # `state` into a session that will be lost again and loop the browser, so
      # fail closed.
      assert conn.private[:authentication_result] == {:error, nil}
      refute conn.status == 302
      refute conn.status == 200
    end

    test "the restart pre-exchanges the launch code (read-only) then redirects" do
      import Mimic

      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)
      # Opt into the read-only pre-exchange (a same-host tenant-aware secret
      # would read the surfaced profile). Without this — and without an
      # `idp_initiated_request_url` — the restart is a plain redirect, no
      # exchange.
      strategy = %{strategy | resolve_idp_initiated_launch?: true}
      user_info = %{"sub" => "person-123", "email" => "teacher@school.example"}
      test_pid = self()

      # The read-only pre-exchange runs against the launch's `code` and yields
      # the profile the restart surfaces (as `:idp_initiated_user_info`) to the
      # request phase's secret-resolution context — the seam a multi-tenant
      # `authorize_url`/`redirect_uri` secret reads to route the restart at the
      # launch's tenant. We assert the exchange happens with the inbound code.
      stub(Assent.Strategy.OAuth2, :callback, fn _config, params ->
        send(test_pid, {:pre_exchanged, params})
        {:ok, %{user: user_info, token: %{"access_token" => "at"}}}
      end)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # The launch code was exchanged read-only, before the restart...
      assert_received {:pre_exchanged, %{"code" => "abc"}}

      # ...and the restart still happened: a 302 into the authorize endpoint,
      # minting a fresh `state`. No user was signed in from the inbound code.
      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      assert String.starts_with?(location, "https://example.com/authorize?")
      assert get_session(conn, "user/oauth2_idp_initiated").state =~ ~r/.+/
      refute match?({:ok, _}, conn.private[:authentication_result])
    end

    test "without opt-in, the restart does NOT pre-exchange (no wasted round-trip)" do
      import Mimic

      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)
      # No `resolve_idp_initiated_launch?`, no `idp_initiated_request_url`:
      # nothing consumes the launch profile, so the restart must be a plain
      # redirect with zero token/profile calls.
      reject(&Assent.Strategy.OAuth2.callback/3)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      assert String.starts_with?(location, "https://example.com/authorize?")
      assert get_session(conn, "user/oauth2_idp_initiated").state =~ ~r/.+/
    end

    test "a conn-aware resolve_idp_initiated_launch? secret skips the pre-exchange per-request" do
      import Mimic

      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)
      # A module secret that gates on the request: this conn has no `resolve=1`
      # param, so it returns false and the pre-exchange must NOT run.
      strategy = %{
        strategy
        | resolve_idp_initiated_launch?: {__MODULE__.ResolveOnParamSecret, []}
      }

      reject(&Assent.Strategy.OAuth2.callback/3)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      assert conn.status == 302
      assert get_session(conn, "user/oauth2_idp_initiated").state =~ ~r/.+/
    end

    test "a failed pre-exchange still restarts (unaffected fall-through)" do
      import Mimic

      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)
      strategy = %{strategy | resolve_idp_initiated_launch?: true}

      # The pre-exchange fails (code already spent, provider error, or a
      # provider that simply cannot pre-resolve the launch). The restart must
      # still happen — with no launch profile — so nothing regresses for a
      # provider that neither needs nor supports pre-resolution.
      stub(Assent.Strategy.OAuth2, :callback, fn _config, _params -> {:error, :boom} end)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      assert conn.status == 302
      assert get_session(conn, "user/oauth2_idp_initiated").state =~ ~r/.+/
    end

    test "when idp_initiated_request_url resolves, the restart is handed off to that host" do
      import Mimic

      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)
      user_info = %{"id" => "person-123"}

      # Per-tenant HOST: the tenant lives on its own host, so the restart must
      # run there (host-scoped `state` cookie). The strategy resolves the
      # tenant's request-phase URL from the launch profile in context. Note
      # this uses a `Secret` *module* — a context-aware secret must be a module
      # (`secret_for/4`); an inline function secret never receives context.
      strategy = %{strategy | idp_initiated_request_url: {__MODULE__.TenantRequestUrlSecret, []}}

      stub(Assent.Strategy.OAuth2, :callback, fn _config, _params ->
        {:ok, %{user: user_info, token: %{"access_token" => "at"}}}
      end)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # Redirected to the resolved tenant host's request phase — NOT the
      # authorize endpoint, and NO `state` stored here: the target host runs
      # the request phase and stores `state` where the callback will read it.
      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      assert location == "https://person-123.example.com/auth/user/oauth2_idp_initiated"
      assert is_nil(get_session(conn, "user/oauth2_idp_initiated"))
    end
  end

  defmodule TenantRequestUrlSecret do
    @moduledoc false
    use AshAuthentication.Secret

    @impl true
    def secret_for(_secret_name, _resource, _opts, %{idp_initiated_user_info: %{"id" => id}}),
      do: {:ok, "https://#{id}.example.com/auth/user/oauth2_idp_initiated"}

    def secret_for(_secret_name, _resource, _opts, _context), do: :error
  end

  defmodule ResolveOnParamSecret do
    @moduledoc false
    use AshAuthentication.Secret

    # Decide per-request from the conn: pre-exchange only when `resolve=1`.
    @impl true
    def secret_for(_secret_name, _resource, _opts, %{conn: conn}),
      do: {:ok, conn.params["resolve"] == "1"}

    def secret_for(_secret_name, _resource, _opts, _context), do: {:ok, false}
  end
end
