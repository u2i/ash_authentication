<!--
SPDX-FileCopyrightText: 2026 u2i

SPDX-License-Identifier: MIT
-->

# Exploration: context-aware IdP-initiated restart

> Branch: `explore/idp-initiated-context-aware-restart`
> Base: the `idp_initiated_login?` work (`fix/oauth2-allow-empty-session-params`).
> This is a **discussion artifact**, not a finished PR — it shows one way to
> make the plug handle the multi-tenant IdP-initiated case, and notes a lighter
> alternative.

## The problem this addresses

`idp_initiated_login?` restarts the request phase from a stateless callback to
mint a verifiable `state` (OIDC Core §4). The restart re-enters `request/2`,
which resolves `authorize_url` and redirects there.

That works for a **single-tenant** provider. It breaks for a **multi-tenant**
one whose `authorize_url` is per-tenant, because on an IdP-initiated launch the
tenant is only knowable *from the launch itself* — the profile behind the
`code` — which the plain restart never reads. The `authorize_url` secret
function has nothing to route on, so it falls back to a generic
picker/login screen. (Concretely: Ed.link district SSO. A global Clever launch
hits one callback URL with a `code` and no tenant hint; the restart's
`authorize_url` cannot pick the district's integration URL, so the user gets
Ed.link's `/sso/login` org-picker.)

Today the only fix is app-side: a bespoke plug in front of the auth routes that
does a session-less code exchange, reads the profile, resolves the tenant, and
redirects to the tenant context before the real flow runs. Every multi-tenant
IdP-initiated consumer reinvents that. It should be the strategy's job.

## The approach in this branch (prefetch → context)

Two small changes to `AshAuthentication.Strategy.OAuth2.Plug`:

1. **`request/2` → `request/3`** with an optional `context_extra \\ %{}` merged
   into the secret-resolution context (`%{conn: conn}`). This is the seam: a
   `redirect_uri`/`authorize_url`/… secret function already receives a
   `context` — now the request phase can be handed *more* than the conn.

2. **On the `idp_initiated_login?` restart**, before re-entering the request
   phase, do a **read-only** exchange of the launch's `code`, fetch the
   profile, and pass it as `%{idp_initiated_user_info: user_info}` into
   `request/3`. A tenant-aware secret then routes on it:

   ```elixir
   authorize_url fn _secret, %{idp_initiated_user_info: info} ->
     {:ok, tenant_authorize_url(info)}
   end
   ```

Properties, by construction:

- **Read-only.** The prefetch mints no session, token, or user. It only informs
  *where the restart's authorize URL points*. The real, `state`-verified
  authentication is unchanged.
- **Fail-open.** Any prefetch failure (spent code, provider error, a provider
  that cannot pre-resolve) falls through to a plain restart with empty extra
  context. Single-tenant providers and existing behaviour are unaffected — the
  48-test OAuth2/OIDC suite passes untouched, and the pre-existing
  `idp_initiated` tests still hold.
- **Single-use-code safe.** The restart triggers a *fresh* authorize → a fresh
  `code`, so the code consumed by the prefetch is not needed again.

### Cost

The prefetch is one extra token exchange + profile fetch on the
IdP-initiated leg **only** (not the normal flow). For a provider that doesn't
opt a tenant-aware secret into reading `idp_initiated_user_info`, that work is
wasted — see the open question below on gating it.

## Alternative considered (lighter: context-only, no prefetch)

Instead of the plug doing the exchange, just widen the restart's context to
carry the **raw callback params** (incl. the `code`), and let the app's secret
function decide whether to exchange:

```elixir
# plug: request(conn, strategy, %{callback_params: conn.params})
# app:
authorize_url fn _secret, %{callback_params: %{"code" => code}} ->
  {:ok, tenant_url_from_exchange(code)}   # app exchanges if it wants to
end
```

- **Pro:** no exchange in the framework; zero cost for providers that don't use
  it; the plug stays dumb.
- **Con:** every consumer that *does* need it re-implements the session-less
  exchange (the exact boilerplate we're trying to delete), and now inside a
  secret function — an awkward place for an HTTP round-trip. It barely improves
  on today.

**Recommendation:** the prefetch approach is the one worth pursuing — it puts
the mechanism where the knowledge is. The context-only variant is noted only to
show it was weighed.

## Open questions for the maintainer

1. **Gating the prefetch.** Should it run always (simple, but a wasted exchange
   for providers that ignore it), or be opt-in — e.g. a
   `idp_initiated_login? :resolve_tenant` value, or a
   `resolve_idp_initiated_launch?` flag — so only providers that read the
   profile pay for it? Leaning opt-in.
2. **Context key name.** `:idp_initiated_user_info` is explicit; is there a
   convention to match?
3. **Where the pre-exchange config comes from.** This branch reuses the plug's
   own `config_for/2`. If that becomes public (a separate, small change), the
   prefetch and any app code share one config builder.

## Downstream payoff (what this deletes)

Once this lands, the Ed.link stack collapses:

- **`ash_authentication_edlink`** no longer needs `config_for/1` *for this
  purpose* — the plug does the exchange.
- **teamology** deletes its entire `EdlinkIdpSubdomainPlug` (bare-host
  detection, session-less exchange, redirect) and its router wiring. The
  district routing becomes ~5 lines inside the existing `authorize_url` secret
  function:

  ```elixir
  authorize_url fn _secret, ctx ->
    case ctx[:idp_initiated_user_info] do
      %{"id" => person_id} -> district_authorize_url(person_id)
      _ -> {:ok, "/sso/login"}   # unchanged fallback
    end
  end
  ```

The app keeps *only* its genuinely app-specific bit — mapping a person id to a
district URL — and the framework owns the mechanism.
