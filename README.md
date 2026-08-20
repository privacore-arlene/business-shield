# PrivaCore Business Fraud Check

Business-focused fraud screening tool using the **STOP · VERIFY · CALL™** framework.
Prioritizes Business Email Compromise (BEC), banking change fraud, and invoice fraud
for Canadian businesses.

## Tech Stack

- **Frontend:** TanStack Start v1 (React 19, Vite 7, Tailwind CSS v4)
- **Backend:** Supabase Edge Function `check-business-fraud`
- **AI:** Google Gemini via Lovable AI Gateway
- **Threat Intel:** Google Safe Browsing, VirusTotal
- **Security:** Cloudflare Turnstile, namespaced rate limiting
- **Hosting:** Netlify (frontend), Supabase (Edge Functions + DB)

## Project Structure

```
src/                          Frontend application
  routes/index.tsx            Main page (STOP · VERIFY · CALL™ UI)
  components/                 UI components (Turnstile, BusinessFraudCheck)
  lib/business-check.ts       Client-side helper for the Edge Function
deploy/
  supabase-functions/         Edge Function source (deploy to Supabase)
  db/                         SQL migrations (run in Supabase)
  README.md                   Deployment guide
netlify.toml                  Netlify build + redirect config
```

## Deployment

See [`deploy/README.md`](deploy/README.md) for full instructions covering:

1. Run the SQL migration in Supabase
2. Deploy the `check-business-fraud` Edge Function
3. Create Cloudflare Turnstile keys for `check.privacoregroup.com`
4. Connect Netlify to this GitHub repo and set environment variables

## Environment Variables (Netlify)

| Variable | Description |
|----------|-------------|
| `VITE_PC_SUPABASE_URL` | Supabase project URL |
| `VITE_PC_SUPABASE_ANON_KEY` | Supabase publishable/anon key |
| `VITE_PC_TURNSTILE_SITE_KEY` | Cloudflare Turnstile site key |

> **Note:** All secrets (Gemini API key, Safe Browsing key, VirusTotal key,
> Turnstile secret, Supabase service role) live in the Edge Function
> environment on Supabase — never in the frontend.

## STOP · VERIFY · CALL™

Every result follows this framework:
- **STOP** — Don't act on the request yet
- **VERIFY** — Check the indicators against known threats
- **CALL** — Contact the verified party through a known-good channel

Risk levels: `HIGH RISK` · `SUSPICIOUS` · `NO KNOWN THREAT DETECTED` · `INSUFFICIENT EVIDENCE`
