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
grants — they are reachable only by the Netlify server function's service role.

## 2. Backend: Netlify server function

The backend runs **inside the app on Netlify** at
`POST /api/public/check-business-fraud` (source:
`src/routes/api/public/check-business-fraud.ts`). No Supabase Edge Function is
deployed or used; the former reference copy under
`deploy/supabase-functions/` has been removed.

Supabase is still used, unchanged, for the `pc_business_*` rate-limit RPCs;
the server function reaches them over PostgREST with the service-role key.

### Secrets (Netlify → Site configuration → Environment variables)

All of these are **server-only** — never prefixed with `VITE_`, never sent to
the browser, and read at request time inside the handler.

| Secret | Required | Notes |
| --- | --- | --- |
| `PC_SUPABASE_URL` | yes | Existing Supabase project URL (the one holding `pc_business_*`). |
| `PC_SUPABASE_SERVICE_ROLE_KEY` | yes | Service-role key for the `pc_business_*` RPCs only. |
| `PC_TURNSTILE_SECRET` | yes | Turnstile secret for `check.privacoregroup.com`. Verification fails closed without it. |
| `PC_AI_API_KEY` | yes | Your own Gemini API key. |
| `PC_AI_MODEL` | optional | Defaults to `gemini-2.5-pro`. |
| `PC_AI_BASE_URL` | optional | Defaults to Gemini's OpenAI-compatible endpoint. |
| `PC_GOOGLE_WEB_RISK_API_KEY` | recommended | URL reputation via the Web Risk Lookup API (uris.search), commercially licensed. |
| `PC_VIRUSTOTAL_API_KEY` | recommended | Lookup only; URLs are never submitted. |
| `PC_IP_HASH_KEY` | recommended | Long random string; salts the IP HMAC. |
| `PC_ALLOWED_ORIGINS` | optional | Comma-separated exact origins for previews. No wildcards. |

### No longer needed in Supabase

`PC_LOVABLE_API_KEY` is no longer used anywhere. `PC_TURNSTILE_SECRET` must now
live in **Netlify**; the copy in Supabase edge-function secrets is unused and
can be removed. The `pc_business_*` tables and RPCs stay exactly as they are.

## 3. Turnstile

Create a **new** Turnstile site (do not reuse an existing one) with hostnames
`check.privacoregroup.com` plus any preview hostname. The widget is rendered
with action `check-business-fraud`; the function rejects tokens whose hostname
or action does not match.

## 4. Netlify

`netlify.toml` builds with the Netlify server preset. Alongside the server
secrets above, set the single public variable:

```
VITE_PC_TURNSTILE_SITE_KEY
```

The browser no longer needs the Supabase URL or anon key: it calls the
same-origin route `/api/public/check-business-fraud`.

Then add `check.privacoregroup.com` as the custom domain and add that exact
origin to the function's allow-list (it is already the built-in default).

## 5. Secret hygiene

No `.env` file is committed. `.env.example` documents the single public
`VITE_*` value only. The service-role key, Turnstile secret and provider API
keys exist solely as Netlify environment variables, are read inside the server
handler, and are never exposed to the browser or the GitHub repository.