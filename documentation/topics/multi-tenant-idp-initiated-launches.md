<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Multi-Tenant IdP-Initiated Launches

`idp_initiated_login?` (see the `AshAuthentication.Strategy.OAuth2.Dsl` option) lets a strategy
recover from a stateless callback — a launch that arrives with a `code` but no session, because
the identity provider redirected straight to your app instead of the user starting at your sign-in
page (an app-launcher tile, a portal button, an aggregator like Clever or ClassLink). It restarts
the OAuth2 request phase, which mints a verifiable `state` and completes normally.

That restart has no way to pick a **tenant**. On a single-tenant app there's nothing to pick. On a
multi-tenant app, the restart needs to know which tenant's `authorize_url`/`redirect_uri` to use —
and on an IdP-initiated launch, the only place that information can come from is the launch
itself, which the plain restart never reads.

This guide is not a new library feature — it's how to write the plug that reads it, using two
small functions `AshAuthentication.Strategy.OAuth2.Plug` exposes for exactly this:

- `assent_config/2` — the same Assent config `request/2`/`callback/2` build internally, so your
  plug talks to the provider with a config that actually matches your strategy, instead of a
  hand-picked subset that happens to work today and quietly stops matching the moment your
  strategy's auth method changes.
- `fetch_idp_launch_profile/2` — a read-only exchange of the inbound `code`, with the same
  `assent_config/2` and the three opt-outs (`state: false`, `code_verifier: false`, an empty
  `session_params`) that let you peek at *who* is launching without completing authentication.
  Assent's own docs call `session_params` optional on `callback/3`; the code requires the key, so
  getting this by hand is an easy way to ship a crash on your first real launch.

## Two deployment shapes

**Same-host tenants** — one process serves every tenant (Ash's `multitenancy strategy:
:attribute`/`:context`). Resolve the tenant and set it on the conn; the restart picks it up like
any other request.

**Per-tenant-host tenants** — each tenant is served from its own subdomain/domain. The request
phase has to run *on that host*, because `state` is stored in a session cookie scoped to whichever
host serves it — restarting on the wrong host and then handing the result to the tenant's host
would strand the `state` the callback needs to verify. Redirect the browser to the tenant's host
instead of restarting locally.

Both shapes share the same first step (read the launch, resolve the tenant); they differ only in
what happens once you know it.

## Example: same-host tenant, resolved from the launch profile

```elixir
defmodule MyAppWeb.Plugs.ResolveIdpInitiatedTenant do
  @moduledoc """
  For a strategy with `idp_initiated_login? true`: a launch arriving on the
  shared host with a `code` and no session can't resolve a tenant from the
  request alone. Peek at the launch's profile (read-only) and set the
  tenant on the conn before AshAuthentication's own plug runs.
  """
  @behaviour Plug
  import Plug.Conn
  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

  @resource MyApp.Accounts.User
  @strategy_name :my_provider

  def init(opts), do: opts

  def call(conn, _opts) do
    conn = fetch_query_params(conn)

    with nil <- Ash.PlugHelpers.get_tenant(conn),
         %{"code" => code} when code != "" <- conn.params,
         strategy <- Info.strategy!(@resource, @strategy_name),
         {:ok, %{user: profile}} <- Plug.fetch_idp_launch_profile(strategy, conn),
         {:ok, tenant} <- resolve_tenant(profile) do
      Ash.PlugHelpers.set_tenant(conn, tenant)
    else
      _ -> conn
    end
  end

  # The one app-specific piece: map a claim from the provider's profile
  # (an issuer, an org id, a stable subject) to your tenant identifier.
  defp resolve_tenant(%{"org_id" => org_id}) when is_binary(org_id),
    do: MyApp.Accounts.tenant_by_external_org_id(org_id)

  defp resolve_tenant(_), do: :error
end
```

Mount it ahead of your auth routes:

```elixir
pipeline :browser do
  # ...
  plug MyAppWeb.Plugs.ResolveIdpInitiatedTenant
end
```

If the launch carries a real tenant hint already — a query param, a distinct `client_id`/
`redirect_uri` per tenant — resolve it from `conn.params`/the host directly and skip
`fetch_idp_launch_profile/2` entirely; the exchange only earns its cost when nothing else in the
request tells you the tenant.

## Example: per-tenant-host, redirecting instead of setting a tenant

Same plug, different last step — instead of `set_tenant/2`, redirect and halt so the request phase
runs on the tenant's own host:

```elixir
defp resolve_tenant(%{"org_id" => org_id}) do
  case MyApp.Accounts.subdomain_by_external_org_id(org_id) do
    subdomain when is_binary(subdomain) -> {:redirect, "https://#{subdomain}.myapp.com/auth/user/my_provider"}
    _ -> :error
  end
end
```

```elixir
def call(conn, _opts) do
  conn = fetch_query_params(conn)

  with nil <- Ash.PlugHelpers.get_tenant(conn),
       %{"code" => code} when code != "" <- conn.params,
       strategy <- Info.strategy!(@resource, @strategy_name),
       {:ok, %{user: profile}} <- Plug.fetch_idp_launch_profile(strategy, conn),
       {:redirect, url} <- resolve_tenant(profile) do
    conn
    |> put_resp_header("location", url)
    |> send_resp(:found, "Redirecting")
    |> halt()
  else
    _ -> conn
  end
end
```

The tenant's own host then runs `request/2` fresh — same strategy config, but its
`authorize_url`/`redirect_uri` secrets now resolve using *that* host — and stores `state` where
the eventual callback, on that same host, can read it back.

## Sequence of events

Route paths are `AshAuthentication`'s own: request phase `/<subject_name>/<strategy>`, callback
`/<subject_name>/<strategy>/callback`, under your app's auth prefix (e.g. `/auth`).

### Same-host

```
1. IdP  ──GET──▶  app.example.com/auth/user/my_provider/callback?code=X
                  (no `state`, no session -- a bare IdP-initiated launch)

2. Your plug, same request, same host:
      server ──POST──▶ idp.example.com/oauth/token   (exchange `code`, read-only)
      server ──GET───▶ idp.example.com/userinfo      (fetch profile)
   Resolves tenant from the profile, calls `set_tenant/2`.
   No response sent yet -- the conn continues down the pipeline.

3. AshAuthentication's OAuth2.Plug.callback/2 finds no session and
   (idp_initiated_login? true, no `state` param) calls request/2 IN-PROCESS --
   steps 2-3 are all one response to the single request from step 1:
      app  ──302────▶  browser
      Location: idp.example.com/authorize?...&state=<fresh>&redirect_uri=
                app.example.com/auth/user/my_provider/callback
      (the fresh `state` is stored in a session cookie scoped to
       app.example.com, set on this same response)

4. Browser has a live IdP session, so the IdP immediately redirects back
   with a NEW single-use `code` and the `state` from step 3:
      idp  ──302────▶  browser
      Location: app.example.com/auth/user/my_provider/callback?code=Y&state=...

5. This callback carries the session cookie from step 3 (same host) --
   AshAuthentication's normal path runs: `state` verifies against the
   session, the code from step 4 (never the one from step 1) is exchanged
   for real, and sign-in completes.
```

### Per-tenant-host

Same steps 1-2; step 3 differs — the plug hands off to the tenant's host instead of letting
`AshAuthentication` restart on the bare host:

```
3. Your plug redirects the browser and HALTS -- the bare host's
   OAuth2.Plug.callback/2 never runs for this request:
      app  ──302────▶  browser
      Location: tenant.app.example.com/auth/user/my_provider

4. AshAuthentication's routes on the TENANT's host run request/2 fresh
   (same strategy config; `authorize_url`/`redirect_uri` secrets now
   resolve using THIS host):
      tenant.app  ──302────▶  browser
      Location: idp.example.com/authorize?...&state=<fresh>&redirect_uri=
                tenant.app.example.com/auth/user/my_provider/callback
      (the fresh `state` is stored in a session cookie scoped to
       tenant.app.example.com -- the host that will receive the callback)

5-6. Same as the same-host case's steps 4-5, on tenant.app.example.com:
     the IdP redirects back with a new `code` + `state`, the tenant host's
     own cookie verifies `state`, sign-in completes.
```

Why cross-host needs its own request-phase run (step 4): browsers scope cookies per host, so a
`state` stored on `app.example.com` can never be verified by `tenant.app.example.com`'s callback.
Restarting on the bare host and 302'ing the result across would strand the `state`.

## Security notes

`fetch_idp_launch_profile/2` mints no session, token, or user — it exists only to read *who* is
launching, before anything is verified. Treat the result accordingly:

- The exchanged `code` is consumed here, but the restart (`request/2`) mints a fresh `code`/`state`
  via a new `authorize_url` redirect, so the code spent on the read is never reused — the real
  sign-in is independently `state`-verified as usual.
- The profile is provider-authenticated (a real token exchange happened) but **not** bound to the
  current browser session — it may belong to an attacker who has their own account at the same
  provider and crafted a callback URL with their own `code`. Use it for routing only. Never sign
  in, provision, or authorize a user from it directly.
- Validate any redirect target derived from the profile against an allowlist or a database lookup
  — as in the examples above, where the target comes from a lookup keyed on the profile's `org_id`,
  never from an unvalidated field echoed straight into a URL. Echoing profile data into a redirect
  is an open-redirect primitive.
