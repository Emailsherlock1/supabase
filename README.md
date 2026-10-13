# EmailSherlock Email-Guard — Supabase auth hook

Block disposable and undeliverable email addresses at Supabase signup. This is a
[Supabase Edge Function](https://supabase.com/docs/guides/functions) that serves
the [Before User Created](https://supabase.com/docs/guides/auth/auth-hooks/before-user-created-hook)
auth hook: Supabase calls it before it creates a new user, and the function asks
the [EmailSherlock](https://www.hostsherlock.com) verify API whether to allow or
reject the signup.

It is a thin client over the public API at `api.emailsherlock.com`; there is no
separate backend. Jira: EM-1030 (part of the Email-Guard epic, EM-956).

## How it works

1. A user signs up. Supabase POSTs the new user to this function before creating
   the row.
2. The function calls `POST /v1/verify/single` with the address.
3. It maps the verify `decision.recommendation` (`allow` / `deny` / `review`)
   against your `block_on` policy.
4. Blocked: it returns a rejection and Supabase refuses the signup. Otherwise it
   returns an empty allow and the signup proceeds.

It **fails open**. If the verify API times out, errors, or no key is configured,
the signup is allowed and the reason is logged. An API hiccup never blocks a
legitimate user. Set `EMAILSHERLOCK_FAIL_OPEN=false` to fail closed instead.

## The contract

This matches the Supabase Before User Created hook:

| Direction | Shape |
|---|---|
| Request | `POST` with `{ metadata: { ip_address, ... }, user: { email, app_metadata: { provider }, ... } }` |
| Allow | `200` with `{}` |
| Reject | `4xx` with `{ "error": { "message": "...", "http_code": 400 } }` |

The hook runs **before a JWT is issued**, so the function is deployed with
`verify_jwt = false` (see `supabase/config.toml`). Authenticity is protected by a
[Standard Webhooks](https://www.standardwebhooks.com/) signature instead. Set
`EMAILSHERLOCK_HOOK_SECRET` to the secret from the Supabase Auth Hooks dashboard
and every request is signature-checked. A bad signature is rejected regardless of
fail-open.

## Setup

You need the [Supabase CLI](https://supabase.com/docs/guides/local-development)
and an EmailSherlock API key from [hostsherlock.com/api](https://www.hostsherlock.com/api).

```bash
# 1. From a project that has this repo's `supabase/` directory:
supabase functions deploy email-guard --no-verify-jwt

# 2. Set the secrets (or `supabase secrets set --env-file .env`):
supabase secrets set \
  EMAILSHERLOCK_API_KEY=es_live_xxx \
  EMAILSHERLOCK_HOOK_SECRET=v1,whsec_xxx
```

Then in the Supabase dashboard: **Authentication → Hooks → Before User Created**,
point the hook at the function URL
(`https://<project-ref>.supabase.co/functions/v1/email-guard`) and copy the
generated secret into `EMAILSHERLOCK_HOOK_SECRET`.

Use a **sandbox key** (`es_test_`) while testing: it returns fixtured results and
spends no credits.

## Configuration

All via function secrets (see `.env.example`):

| Variable | Default | What it does |
|---|---|---|
| `EMAILSHERLOCK_API_KEY` | _(none)_ | Required for live verification. Without it, every signup is allowed (fail open). |
| `EMAILSHERLOCK_HOOK_SECRET` | _(none)_ | Standard Webhooks secret. When set, requests are signature-checked. |
| `EMAILSHERLOCK_BLOCK_ON` | `deny` | Comma list of `allow`/`deny`/`review` that reject the signup. Add `review` to also block role / catch-all / uncertain addresses. |
| `EMAILSHERLOCK_FAIL_OPEN` | `true` | `false` rejects when the API can't give a verdict. |
| `EMAILSHERLOCK_TIMEOUT_MS` | `800` | Verify call timeout. |
| `EMAILSHERLOCK_REJECT_MESSAGE` | generic | Message shown to a rejected user. |
| `EMAILSHERLOCK_GUARD_TELEMETRY` | `false` | `true` sends best-effort domain-only telemetry (never the full address). |
| `EMAILSHERLOCK_API_BASE_URL` | `https://api.emailsherlock.com` | Override for a staging host. |

Policy belongs to you. The defaults block obvious junk (disposable, undeliverable)
and let everything else through.

## Local development

```bash
cp .env.example .env          # add a sandbox key
supabase functions serve email-guard --no-verify-jwt --env-file .env

# In another shell, simulate a Before User Created call:
curl -i http://localhost:54321/functions/v1/email-guard \
  -H 'content-type: application/json' \
  -d '{"user":{"email":"test@mailinator.com"}}'
# disposable -> 400 with an error body. A real address -> 200 {}.
```

When `EMAILSHERLOCK_HOOK_SECRET` is set you must send a valid Standard Webhooks
signature, so leave it unset for plain local curl tests.

## Publishing

This directory is pushed to its own repo for release:

```bash
cd supabase
git init && git add -A && git commit -m "Initial release 0.1.0"
git branch -M main
git remote add origin git@github.com:Emailsherlock1/supabase.git
git push -u origin main
```

The `/integrations` directory card on emailsherlock.com is added only after the
repo is public (no vaporware cards).
