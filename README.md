# PrivaCore Business Fraud Check

Business-focused fraud screening tool using the **STOP · VERIFY · CALL™** framework.
Prioritizes Business Email Compromise (BEC), banking change fraud, and invoice fraud
for Canadian businesses.

## Tech Stack

- **Frontend:** TanStack Start v1 (React 19, Vite 7, Tailwind CSS v4)
- **Backend:** Netlify server function at `POST /api/public/check-business-fraud`
  (source: `src/routes/api/public/check-business-fraud.ts`). No Supabase Edge
  Function is used or deployed.
- **AI:** Google Gemini (OpenAI-compatible endpoint) with your own key
- **Threat Intel:** Google Web Risk, VirusTotal (lookup only)
- **Security:** Cloudflare Turnstile, namespaced rate limiting
- **Hosting:** Netlify (frontend + server function); Supabase used only for the
  `pc_business_*` rate-limit tables/RPCs

## Project Structure

```
src/                          Frontend application
  routes/index.tsx            Main page (STOP · VERIFY · CALL™ UI)
  components/                 UI components (Turnstile, BusinessFraudCheck)
  lib/business-check.ts       Client-side helper (same-origin fetch)
  lib/business-fraud/*.server.ts  Server-only modules (never bundled to browser)
  routes/api/public/check-business-fraud.ts  Server function (the whole backend)
deploy/
  db/                         SQL migrations (run in Supabase)
  README.md                   Deployment guide
netlify.toml                  Netlify build config (publish = "dist")
```

## Deployment

See [`deploy/README.md`](deploy/README.md) for full instructions covering:

1. Run the SQL migration in Supabase (creates the `pc_business_*` objects)
2. Create Cloudflare Turnstile keys for `check.privacoregroup.com`
3. Connect Netlify to this GitHub repo and set the environment variables below

## Environment Variables (Netlify)

Public (ships in the browser bundle):

| Variable | Description |
|----------|-------------|
| `VITE_PC_TURNSTILE_SITE_KEY` | Cloudflare Turnstile **site** key |

Server-only (read inside the server function, never sent to the browser):
`PC_SUPABASE_URL`, `PC_SUPABASE_SERVICE_ROLE_KEY`, `PC_TURNSTILE_SECRET`,
`PC_AI_API_KEY`, `PC_AI_MODEL` (optional), `PC_AI_BASE_URL` (optional),
`PC_GOOGLE_WEB_RISK_API_KEY`, `PC_VIRUSTOTAL_API_KEY`, `PC_IP_HASH_KEY`,
`PC_ALLOWED_ORIGINS` (optional).

> `PC_LOVABLE_API_KEY` is no longer used anywhere. The Turnstile secret lives in
> Netlify, not Supabase.

## STOP · VERIFY · CALL™

Every result follows this framework:
- **STOP** — Don't act on the request yet
- **VERIFY** — Check the indicators against known threats
- **CALL** — Contact the verified party through a known-good channel

Risk levels: `HIGH RISK` · `SUSPICIOUS` · `NO KNOWN THREAT DETECTED` · `INSUFFICIENT EVIDENCE`
