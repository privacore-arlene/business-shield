# PrivaCore Business Fraud Check — deployment

Lovable → GitHub (`privacore-arlene/business-shield`) → Netlify.
Production domain: **https://check.privacoregroup.com**

Nothing in this repository reads, writes or calls any Fraud Doctor resource.

---

## 1. Database (existing Supabase project, namespaced)

Run `deploy/db/20260101000000_pc_business_rate_limits.sql` in the Supabase SQL
editor. It creates PrivaCore-only objects:

| Object | Purpose |
| --- | --- |
| `pc_business_daily_checks` | per-device daily allowance (5/day) |
| `pc_business_ip_checks` | per-network ceilings (20/day, 8 per 10 min) |
| `pc_consume_business_daily_check()` | device allowance RPC |
| `pc_consume_business_ip_check()` | network ceiling RPC |
| `pc_purge_business_usage()` | 30-day retention cleanup |

Both tables have RLS enabled with **no policies** and no anon/authenticated
grants — they are reachable only by the edge function's service role.

## 2. Edge function

Copy `deploy/supabase-functions/check-business-fraud/` into
`supabase/functions/check-business-fraud/` in a Supabase CLI workspace and
deploy:

```sh
supabase functions deploy check-business-fraud --project-ref <ref>
```

### Secrets (Supabase → Edge Functions → Secrets)

Every name is `PC_`-prefixed so PrivaCore credentials can be rotated without
touching Fraud Doctor. Where a `PC_` secret is absent the function falls back
to the shared platform value, so set the PrivaCore ones explicitly.

| Secret | Required | Notes |
| --- | --- | --- |
| `PC_TURNSTILE_SECRET` | yes | **New** Turnstile secret for `check.privacoregroup.com`. Verification fails closed without it. |
| `PC_LOVABLE_API_KEY` | yes | AI Gateway key. |
| `PC_GOOGLE_SAFE_BROWSING_API_KEY` | recommended | URL reputation. |
| `PC_VIRUSTOTAL_API_KEY` | recommended | Lookup only; URLs are never submitted. |
| `PC_IP_HASH_KEY` | recommended | Long random string; salts the IP HMAC. |
| `PC_SUPABASE_URL` / `PC_SUPABASE_SERVICE_ROLE_KEY` | optional | Only if pointing at a different project than the function's own. |
| `PC_EXTRA_ALLOWED_ORIGINS` | optional | Comma-separated exact origins for local dev / Netlify previews. No wildcards. |

## 3. Turnstile

Create a **new** Turnstile site (do not reuse an existing one) with hostnames
`check.privacoregroup.com` plus any preview hostname. The widget is rendered
with action `check-business-fraud`; the function rejects tokens whose hostname
or action does not match.

## 4. Netlify

`netlify.toml` builds with the Netlify server preset and publishes
`dist/client`. Set these environment variables in Netlify (all public):

```
VITE_PC_SUPABASE_URL
VITE_PC_SUPABASE_ANON_KEY
VITE_PC_TURNSTILE_SITE_KEY
```

Then add `check.privacoregroup.com` as the custom domain and add that exact
origin to the function's allow-list (it is already the built-in default).

## 5. Secret hygiene

No `.env` file is committed. `.env.example` documents the three public
`VITE_*` values only. Service-role keys, the Turnstile secret and provider API
keys exist solely as Supabase edge function secrets and are never exposed to
the browser.