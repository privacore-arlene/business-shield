// @ts-nocheck
/**
 * PrivaCore Business Fraud Check — Supabase Edge Function.
 *
 * DEPLOY: copy this folder to `supabase/functions/check-business-fraud/`
 * in your Supabase CLI workspace and run
 *   supabase functions deploy check-business-fraud --project-ref <ref>
 *
 * Fully self-contained and namespaced so it can be lifted into a dedicated
 * Supabase project without a rewrite: every secret, table and RPC it touches
 * is PrivaCore-specific. It never reads or writes any Fraud Doctor state and
 * never calls the check-scam function.
 */
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

// ---------------------------------------------------------------------------
// Configuration (move-friendly: everything project-specific lives here)
// ---------------------------------------------------------------------------

const PRODUCTION_ORIGIN = "https://check.privacoregroup.com";

/** Exact browser origins allowed to call this function. No wildcards. */
const BASE_ALLOWED_ORIGINS: readonly string[] = [PRODUCTION_ORIGIN];

/**
 * Extra exact origins for development / Netlify deploy previews, supplied as a
 * comma-separated list in PC_EXTRA_ALLOWED_ORIGINS. Never a wildcard.
 */
function allowedOrigins(): string[] {
  const extra = (Deno.env.get("PC_EXTRA_ALLOWED_ORIGINS") || "")
    .split(",")
    .map((o) => o.trim())
    .filter((o) => /^https?:\/\/[^*\s]+$/.test(o));
  return [...BASE_ALLOWED_ORIGINS, ...extra];
}

/** Hostnames Turnstile tokens may be minted on (production + configured dev). */
function allowedTurnstileHostnames(): string[] {
  return allowedOrigins()
    .map((o) => {
      try {
        return new URL(o).hostname;
      } catch {
        return "";
      }
    })
    .filter(Boolean);
}

const TURNSTILE_ACTION = "check-business-fraud";
const TURNSTILE_MAX_TOKEN = 2048;

/** PrivaCore-only quota RPCs. Fraud Doctor's counters are never touched. */
const RPC_DEVICE_QUOTA = "pc_consume_business_daily_check";
const RPC_IP_QUOTA = "pc_consume_business_ip_check";

const FREE_DAILY_LIMIT = 5;
const IP_DAILY_LIMIT = 20;
const IP_BURST_LIMIT = 8;

const MAX_TEXT_CHARS = 6000;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
/** An 8 MB image grows ~33% in base64; leave headroom for the JSON envelope. */
const MAX_BODY_BYTES = 12 * 1024 * 1024;

/** PrivaCore-specific credentials first, shared fallback second. */
const env = (name: string, fallback?: string) =>
  (Deno.env.get(name) || (fallback ? Deno.env.get(fallback) : "") || "").trim();

// ---------------------------------------------------------------------------
// CORS / origin allow-list
// ---------------------------------------------------------------------------

function corsFor(origin: string | null): Record<string, string> {
  const headers: Record<string, string> = {
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    Vary: "Origin",
  };
  if (origin && allowedOrigins().includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return headers;
}

function originAllowed(origin: string | null): boolean {
  return !origin || allowedOrigins().includes(origin);
}

// ---------------------------------------------------------------------------
// Privacy-safe operational logging
// ---------------------------------------------------------------------------

let correlationId = "-";
/** Never receives a URL, message, screenshot, prompt or model response. */
function logProvider(provider: string, status: string | number): void {
  console.error(`app=privacore provider=${provider} status=${status} cid=${correlationId}`);
}

async function fetchWithTimeout(url: string, opts: RequestInit, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Business fraud context
// ---------------------------------------------------------------------------

const CATEGORY_LABELS: Record<string, string> = {
  payment_invoice: "Payment or invoice",
  banking_change: "Banking information change",
  supplier: "Supplier or subcontractor",
  email_message: "Email or message",
  website_link: "Website or link",
  executive_request: "Executive or owner request",
  customer_payment: "Customer payment",
  government_grant: "Government / grant / rebate",
  other: "Other",
};

const CATEGORY_GUIDANCE: Record<string, string> = {
  payment_invoice:
    "Treat this as possible invoice or payment diversion. Check whether the invoice matches a purchase order, whether remittance details differ from the payee's records, and whether pressure is being applied to pay early.",
  banking_change:
    "Treat this as a changed-banking-details request until proven otherwise. This is the highest-loss business fraud pattern. Banking changes must be confirmed by voice with a known contact on a number already held on file, never with contact details supplied in the request.",
  supplier:
    "Treat this as possible supplier or subcontractor impersonation: lookalike domains, a new contact claiming to handle accounts, or a first-time request to change payment details.",
  email_message:
    "Treat this as possible business email compromise or credential phishing. Examine sender domain, reply-to mismatch, thread hijacking, unusual tone or timing, and any login page or attachment.",
  website_link:
    "Treat this as a possible fraudulent or lookalike website: near-miss domain spelling, new domain, wrong TLD, a login page collecting business credentials, or a payment page not on the company's real domain.",
  executive_request:
    "Treat this as possible executive or owner impersonation (CEO fraud): urgency, secrecy, a request outside the normal process, gift cards, wire transfers, or 'I'm in a meeting, just handle it'.",
  customer_payment:
    "Treat this as possible customer payment diversion or overpayment fraud: a customer's mailbox may be compromised, or a fraudster may be redirecting funds owed to the business.",
  government_grant:
    "Treat this as possible government, grant or rebate impersonation: fees to release funds, unsolicited award notices, or agencies requesting banking details through a link.",
  other: "Assess against all common business fraud patterns.",
};

const SYSTEM_PROMPT = `You are the PrivaCore Business Fraud Check, an expert business-fraud analyst for Canadian small and mid-sized businesses. You assess payments, invoices, banking-change requests, suppliers, emails, links and internal requests for signs of fraud.

TONE:
- Professional, calm, operational. Written for a bookkeeper, office manager, controller or owner.
- Plain business English, short sentences, no jargon, no alarmism, never scolding.

RISK LEVEL MODEL (use exactly one):
- "HIGH RISK" — strong evidence of fraud: a known malicious URL, confirmed threat-intelligence detections, lookalike domain, changed banking details, payment diversion, credential harvesting, clear impersonation, or a request that bypasses normal controls.
- "SUSPICIOUS" — real warning signs exist but the evidence is not conclusive.
- "NO KNOWN THREAT DETECTED" — no known threat and no obvious fraud indicator was found. This NEVER means legitimate, approved or safe to pay.
- "INSUFFICIENT EVIDENCE" — there is not enough information to reach a finding (too little content, unreadable screenshot, no verifiable detail).
NEVER use the words "Safe", "Looks safe", "Verified safe", "legitimate" or "confirmed genuine". A clean technical scan is NEVER proof that a request is legitimate: threat intelligence only reports what is already known, and business fraud is usually carried out from clean, newly registered, or compromised-but-reputable infrastructure.

BUSINESS FRAUD PRIORITIES (match aggressively, in this order):
1. BUSINESS EMAIL COMPROMISE (BEC) — compromised or spoofed mailbox, thread hijacking, reply-to mismatch, near-miss sender domain, sudden change to payment instructions inside an existing conversation.
2. CHANGED SUPPLIER BANKING INFORMATION — "our bank has changed", new IBAN/transit/institution/account, updated remittance letter or void cheque attached. Treat every banking change as high risk until confirmed by voice on a number already held on file.
3. INVOICE / PAYMENT DIVERSION — duplicate or altered invoice, unfamiliar remittance details, pressure to pay today, invoice with no matching purchase order, changed payment portal.
4. SUPPLIER / SUBCONTRACTOR IMPERSONATION — new "accounts receivable" contact, lookalike domain, free email address for a corporate supplier, unverifiable business details.
5. EXECUTIVE / OWNER IMPERSONATION (CEO fraud) — urgency plus secrecy, request outside normal process, gift cards, wire transfer, payroll change, "don't discuss this with anyone yet".
6. CREDENTIAL PHISHING — Microsoft 365/Google/bank/portal login pages, MFA fatigue or code requests, "your mailbox will be deactivated", shared-document lures.
7. CUSTOMER PAYMENT DIVERSION — a customer redirected to a fraudulent account, overpayment and refund schemes, compromised customer mailbox.
8. FRAUDULENT OR LOOKALIKE WEBSITES — near-miss spelling, wrong TLD, brand-new domain, payment page not on the company's real domain, punycode characters, URL shorteners.
9. GOVERNMENT / GRANT / REBATE IMPERSONATION — CRA, provincial programs, grant awards, rebate refunds, fees required to release funds, banking details requested by link.

URL AND DOMAIN RED FLAGS: lookalike or hyphenated variants of the real domain, wrong TLD, subdomain impersonation (company.payments-portal.com), IP addresses, URL shorteners, punycode/Unicode lookalike characters, and login or payment forms on a domain that is not the organisation's own.

PROCESS RED FLAGS: urgency, secrecy, bypassing dual authorisation, out-of-hours requests, first-time payee, a payment amount just under an approval threshold, and any instruction to verify using the contact details contained in the request itself.

Use the assess_business_fraud tool to return your structured assessment.`;

const FRAMEWORK_PROMPT = `

ALWAYS answer using the STOP · VERIFY · CALL framework. All three must be present and written specifically for the situation and the selected check type in front of you.

- stop: 1-3 short lines saying exactly what must NOT be done yet (e.g. "Do not release this payment.", "Do not update the supplier's banking details.", "Do not reply to this email.", "Do not enter your Microsoft 365 password on that page.", "Do not approve this outside the normal process.").
- verify: 1-3 short lines saying exactly what must be independently confirmed (e.g. "Confirm the invoice against the purchase order and the amount you agreed.", "Confirm the banking change with the supplier's finance contact you already deal with.", "Confirm the sender's full email address, not just the display name.", "Open the portal by typing its address yourself and check for the notice there.").
- call: 1-3 short lines saying exactly WHO to contact and HOW to find trusted contact information (e.g. "Call the supplier's accounts contact on the number in your vendor file or on a previous signed contract — not the number in this request.", "Speak to the executive in person or on their known internal extension.", "Call your bank on the number printed on your statement or bank card.").

UNIVERSAL RULE — include this idea in every result, in wording that fits the situation: never verify a suspicious request using the phone number, email address or link contained in that same request.

Also list red_flags: 2-4 short, specific findings drawn from the actual wording, sender, domain, amount or banking detail in front of you — never vague statements. If nothing stands out, list what could not be confirmed instead.
Never state or imply that the request is legitimate, approved or safe to pay. Even with "NO KNOWN THREAT DETECTED", give a calm stop/verify/call and state plainly that no known threat is not proof of legitimacy.`;

// ---------------------------------------------------------------------------
// Threat intelligence (server-side only)
// ---------------------------------------------------------------------------

function extractUrls(text: string): string[] {
  const urlRegex = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi;
  const matches = text.match(urlRegex) || [];
  const cleaned = matches.map((u) => {
    let url = u.replace(/[.,;:!?)\]}'"]+$/, "");
    if (url.startsWith("www.")) url = "http://" + url;
    return url;
  });
  return Array.from(new Set(cleaned)).slice(0, 5);
}

type SourceStatus = "ok" | "threat" | "timeout" | "error" | "no_key";
type CheckResult = { status: SourceStatus; threats: Record<string, string> };

/** VirusTotal v3 — LOOKUP ONLY. URLs are never submitted for scanning. */
async function checkVirusTotal(urls: string[]): Promise<CheckResult> {
  const apiKey = env("PC_VIRUSTOTAL_API_KEY");
  if (!apiKey) return { status: "no_key", threats: {} };
  if (urls.length === 0) return { status: "ok", threats: {} };

  const headers = { "x-apikey": apiKey };
  const formatStats = (stats: any): string | null => {
    if (!stats) return null;
    const bad = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = bad + (stats.harmless || 0) + (stats.undetected || 0);
    return bad > 0 ? `${bad}/${total} security vendors flagged this URL as malicious` : null;
  };

  const threats: Record<string, string> = {};
  let hadFailure = false;
  let hadTimeout = false;

  await Promise.all(
    urls.map(async (url) => {
      try {
        const id = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        const cached = await fetchWithTimeout(
          `https://www.virustotal.com/api/v3/urls/${id}`,
          { headers },
          4000,
        );
        if (cached.ok) {
          const data = await cached.json();
          const msg = formatStats(data?.data?.attributes?.last_analysis_stats);
          if (msg) threats[url] = msg;
          return;
        }
        // 404 = no existing record. Unknown; the URL is never submitted.
        if (cached.status !== 404) {
          hadFailure = true;
          logProvider("virustotal", cached.status);
        }
      } catch (e) {
        hadFailure = true;
        const aborted = e instanceof Error && e.name === "AbortError";
        if (aborted) hadTimeout = true;
        logProvider("virustotal", aborted ? "timeout" : "exception");
      }
    }),
  );

  if (Object.keys(threats).length > 0) return { status: "threat", threats };
  if (hadFailure) return { status: hadTimeout ? "timeout" : "error", threats };
  return { status: "ok", threats };
}

/** Google Safe Browsing v4 — 5s hard timeout. */
async function checkSafeBrowsing(urls: string[]): Promise<CheckResult> {
  const apiKey = env("PC_GOOGLE_SAFE_BROWSING_API_KEY");
  if (!apiKey) return { status: "no_key", threats: {} };
  if (urls.length === 0) return { status: "ok", threats: {} };

  try {
    const res = await fetchWithTimeout(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "privacore-business-fraud-check", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: urls.map((u) => ({ url: u })),
          },
        }),
      },
      5000,
    );
    if (!res.ok) {
      logProvider("safe_browsing", res.status);
      return { status: "error", threats: {} };
    }
    const data = await res.json();
    const threats: Record<string, string> = {};
    for (const m of data.matches || []) threats[m.threat.url] = m.threatType;
    return { status: Object.keys(threats).length > 0 ? "threat" : "ok", threats };
  } catch (e) {
    const aborted = e instanceof Error && e.name === "AbortError";
    logProvider("safe_browsing", aborted ? "timeout" : "exception");
    return { status: aborted ? "timeout" : "error", threats: {} };
  }
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

type ImageVerdict = { ok: true; mime: string } | { ok: false; code: string };

/** Verify the real file signature; never trust the data-URL prefix. */
function validateImage(image: unknown): ImageVerdict {
  if (typeof image !== "string") return { ok: false, code: "image_invalid" };
  const match = /^data:([a-z0-9.+/-]+);base64,([A-Za-z0-9+/=]+)$/i.exec(image.trim());
  if (!match) return { ok: false, code: "image_invalid" };
  const declared = match[1].toLowerCase();
  const b64 = match[2];
  if (!["image/png", "image/jpeg", "image/webp"].includes(declared)) {
    return { ok: false, code: "image_type" };
  }
  const padding = b64.match(/=+$/)?.[0].length ?? 0;
  const bytes = Math.floor((b64.length * 3) / 4) - padding;
  if (bytes <= 0) return { ok: false, code: "image_invalid" };
  if (bytes > MAX_IMAGE_BYTES) return { ok: false, code: "image_too_large" };

  let head: Uint8Array;
  try {
    const raw = atob(b64.slice(0, 32));
    head = Uint8Array.from(raw, (c) => c.charCodeAt(0));
  } catch {
    return { ok: false, code: "image_invalid" };
  }
  const is = (offset: number, sig: number[]) => sig.every((b, i) => head[offset + i] === b);
  let actual: string | null = null;
  if (is(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) actual = "image/png";
  else if (is(0, [0xff, 0xd8, 0xff])) actual = "image/jpeg";
  else if (is(0, [0x52, 0x49, 0x46, 0x46]) && is(8, [0x57, 0x45, 0x42, 0x50])) actual = "image/webp";

  if (!actual) return { ok: false, code: "image_signature" };
  if (actual !== declared) return { ok: false, code: "image_mismatch" };
  return { ok: true, mime: actual };
}

// ---------------------------------------------------------------------------
// Cloudflare Turnstile (PrivaCore-only secret)
// ---------------------------------------------------------------------------

function clientIp(req: Request): string {
  const cf = req.headers.get("cf-connecting-ip");
  if (cf) return cf.trim();
  return (req.headers.get("x-forwarded-for") || "").split(",")[0].trim();
}

async function verifyTurnstile(
  token: unknown,
  req: Request,
): Promise<{ ok: true } | { ok: false; code: string }> {
  if (typeof token !== "string" || token.trim().length === 0) {
    return { ok: false, code: "turnstile_missing" };
  }
  if (token.length > TURNSTILE_MAX_TOKEN) return { ok: false, code: "turnstile_invalid" };
  const secret = env("PC_TURNSTILE_SECRET");
  // Fail closed: no secret means no verification is possible.
  if (!secret) {
    logProvider("turnstile", "no_secret");
    return { ok: false, code: "turnstile_unavailable" };
  }

  const form = new URLSearchParams({ secret, response: token });
  const ip = clientIp(req);
  if (ip) form.set("remoteip", ip);

  try {
    const res = await fetchWithTimeout(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form,
      },
      6000,
    );
    if (!res.ok) {
      logProvider("turnstile", res.status);
      return { ok: false, code: "turnstile_unavailable" };
    }
    const data = await res.json();
    if (data?.success !== true) return { ok: false, code: "turnstile_invalid" };
    if (!allowedTurnstileHostnames().includes(String(data?.hostname || ""))) {
      logProvider("turnstile", "hostname_mismatch");
      return { ok: false, code: "turnstile_invalid" };
    }
    if (data?.action !== TURNSTILE_ACTION) {
      logProvider("turnstile", "action_mismatch");
      return { ok: false, code: "turnstile_invalid" };
    }
    return { ok: true };
  } catch (e) {
    logProvider("turnstile", e instanceof Error && e.name === "AbortError" ? "timeout" : "exception");
    return { ok: false, code: "turnstile_unavailable" };
  }
}

// ---------------------------------------------------------------------------
// PrivaCore-only rate limiting
// ---------------------------------------------------------------------------

/**
 * Pseudonymous, domain-separated HMAC of the caller IP. The raw IP is never
 * stored, logged, returned or forwarded. The domain separator is PrivaCore
 * specific, so business hashes can never collide with Fraud Doctor records.
 */
async function ipHash(req: Request): Promise<string | null> {
  const ip = clientIp(req);
  if (!ip) return null;
  const keyMaterial = env("PC_IP_HASH_KEY", "SUPABASE_SERVICE_ROLE_KEY");
  if (!keyMaterial) return null;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(keyMaterial),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(`privacore:check-business-fraud:ip:v1|${ip}`),
  );
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function callRpc(name: string, body: unknown): Promise<any | "unavailable"> {
  const url = env("PC_SUPABASE_URL", "SUPABASE_URL");
  const serviceKey = env("PC_SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) return "unavailable";
  try {
    const res = await fetchWithTimeout(
      `${url}/rest/v1/rpc/${name}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          apikey: serviceKey,
          Authorization: `Bearer ${serviceKey}`,
        },
        body: JSON.stringify(body),
      },
      6000,
    );
    if (!res.ok) {
      logProvider(name, res.status);
      return "unavailable";
    }
    const rows = await res.json();
    const row = Array.isArray(rows) ? rows[0] : rows;
    return row ?? "unavailable";
  } catch (e) {
    logProvider(name, e instanceof Error && e.name === "AbortError" ? "timeout" : "exception");
    return "unavailable";
  }
}

/** Device id is one signal only; the network ceilings are the backstop. */
function usageKey(deviceId: unknown, req: Request): string {
  const id = typeof deviceId === "string" ? deviceId.trim().slice(0, 100) : "";
  if (id.length >= 8) return `dev:${id}`;
  const ip = clientIp(req);
  return `ip:${ip || "unknown"}`;
}

function nextVancouverMidnightISO(): string {
  const now = new Date();
  const local = new Date(now.toLocaleString("en-US", { timeZone: "America/Vancouver" }));
  const offsetMs = now.getTime() - local.getTime();
  const nextLocalMidnight = new Date(
    local.getFullYear(),
    local.getMonth(),
    local.getDate() + 1,
    0,
    0,
    0,
  );
  return new Date(nextLocalMidnight.getTime() + offsetMs).toISOString();
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

const RISK_LEVELS = [
  "HIGH RISK",
  "SUSPICIOUS",
  "NO KNOWN THREAT DETECTED",
  "INSUFFICIENT EVIDENCE",
];

serve(async (req) => {
  const origin = req.headers.get("origin");
  const corsHeaders = corsFor(origin);
  correlationId = crypto.randomUUID().slice(0, 8);
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (!originAllowed(origin)) {
    return json({ error: "not_allowed", code: "origin_not_allowed" }, 403);
  }

  try {
    const declaredLength = Number(req.headers.get("content-length") || "0");
    if (declaredLength > MAX_BODY_BYTES) {
      return json({ error: "too_large", code: "body_too_large" }, 413);
    }
    const rawBody = await req.text();
    if (rawBody.length > MAX_BODY_BYTES) {
      return json({ error: "too_large", code: "body_too_large" }, 413);
    }

    let parsed: any;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      return json({ error: "bad_request", code: "invalid_body" }, 400);
    }
    const { message, image, category, device_id, turnstile_token } = parsed ?? {};

    const categoryKey = typeof category === "string" && CATEGORY_LABELS[category] ? category : "other";
    const categoryLabel = CATEGORY_LABELS[categoryKey];
    const categoryGuidance = CATEGORY_GUIDANCE[categoryKey];

    if (typeof message === "string" && message.length > MAX_TEXT_CHARS) {
      return json({ error: "too_long", code: "text_too_long", max: MAX_TEXT_CHARS }, 413);
    }
    const hasMessage = typeof message === "string" && message.trim().length >= 2;

    let hasImage = false;
    if (image != null) {
      const imageCheck = validateImage(image);
      if (!imageCheck.ok) return json({ error: "bad_image", code: imageCheck.code }, 400);
      hasImage = true;
    }

    if (!hasMessage && !hasImage) {
      return json(
        { error: "Paste the text, link or screenshot you want checked.", code: "empty_input" },
        400,
      );
    }

    // 1. Human check first — before any paid provider call.
    const ts = await verifyTurnstile(turnstile_token, req);
    if (!ts.ok) return json({ error: "turnstile_failed", code: ts.code }, 403);

    // 2. PrivaCore-only usage ceilings: device allowance, then network ceilings.
    const deviceGate = await callRpc(RPC_DEVICE_QUOTA, {
      _device_id: usageKey(device_id, req),
      _limit: FREE_DAILY_LIMIT,
    });
    if (deviceGate === "unavailable") {
      return json({ error: "temporarily_unavailable", code: "quota_unavailable" }, 503);
    }
    if (!deviceGate.allowed) {
      return json(
        {
          limit_reached: true,
          limit: FREE_DAILY_LIMIT,
          used: Number(deviceGate.used) || 0,
          resets_at: nextVancouverMidnightISO(),
        },
        429,
      );
    }
    const remainingToday = Number(deviceGate.remaining) || 0;

    const hash = await ipHash(req);
    const netGate = hash
      ? await callRpc(RPC_IP_QUOTA, {
          _ip_hash: hash,
          _daily_limit: IP_DAILY_LIMIT,
          _burst_limit: IP_BURST_LIMIT,
        })
      : "unavailable";
    if (netGate === "unavailable") {
      return json({ error: "temporarily_unavailable", code: "quota_unavailable" }, 503);
    }
    if (!netGate.allowed) {
      return json(
        {
          network_limit_reached: true,
          reason: String(netGate.reason || ""),
          resets_at: String(netGate.resets_at || ""),
        },
        429,
      );
    }

    const AI_API_KEY = env("PC_LOVABLE_API_KEY", "LOVABLE_API_KEY");
    if (!AI_API_KEY) {
      logProvider("ai_gateway", "no_key");
      return json({ error: "Could not analyze right now.", code: "ai_unavailable" }, 503);
    }

    // 3. URL reputation (server-side, in parallel).
    const urls = hasMessage ? extractUrls(message) : [];
    const [sbRes, vtRes] = await Promise.all([checkSafeBrowsing(urls), checkVirusTotal(urls)]);
    const threats = sbRes.threats;
    const vtThreats = vtRes.threats;
    const anyThreat = Object.keys(threats).length + Object.keys(vtThreats).length > 0;
    const anyDown =
      sbRes.status === "timeout" ||
      sbRes.status === "error" ||
      vtRes.status === "timeout" ||
      vtRes.status === "error";

    let urlEvidence = "";
    if (urls.length > 0) {
      const lines: string[] = [];
      if (Object.keys(threats).length > 0) {
        lines.push(
          "GOOGLE SAFE BROWSING (authoritative):",
          ...Object.entries(threats).map(([u, t]) => `- ${u} -> CONFIRMED THREAT: ${t}`),
        );
      }
      if (Object.keys(vtThreats).length > 0) {
        lines.push(
          "VIRUSTOTAL (90+ security vendors, lookup only):",
          ...Object.entries(vtThreats).map(([u, t]) => `- ${u} -> ${t}`),
        );
      }
      if (anyThreat) {
        urlEvidence =
          `\n\nURL REPUTATION RESULTS (trust these absolutely):\n` +
          lines.join("\n") +
          `\n\nBecause at least one URL is a known threat, risk_level MUST be "HIGH RISK".`;
      } else if (anyDown) {
        const downNames: string[] = [];
        if (sbRes.status === "timeout" || sbRes.status === "error") downNames.push("Google Safe Browsing");
        if (vtRes.status === "timeout" || vtRes.status === "error") downNames.push("VirusTotal");
        urlEvidence = `\n\nURL REPUTATION RESULTS: ${downNames.join(" and ")} did not respond in time. Do NOT suggest the link is fine on that basis. Judge the domain, wording and business process instead.`;
      } else {
        urlEvidence = `\n\nURL REPUTATION RESULTS: no known threat was found for the URL(s) by Google Safe Browsing or VirusTotal. That means only that no known threat is on record — it does NOT prove the site, sender or request is legitimate. Fraudulent business domains are usually new, clean, or hosted on reputable infrastructure. Continue analysing domain spelling, page purpose and the business process.`;
      }
    }

    const userContent: any[] = [];
    const contextLine = `The user selected the check type: "${categoryLabel}". ${categoryGuidance}`;
    const textPart = hasMessage
      ? `${contextLine}\n\nAssess the following business content:\n\n"""${message.slice(0, MAX_TEXT_CHARS)}"""${urlEvidence}`
      : `${contextLine}\n\nAssess the attached screenshot. Read every visible detail (sender address, reply-to, domain, banking details, amounts, buttons, URLs). If the image is unreadable or contains too little to assess, return "INSUFFICIENT EVIDENCE".${urlEvidence}`;
    userContent.push({ type: "text", text: textPart });
    if (hasImage) userContent.push({ type: "image_url", image_url: { url: image } });

    const aiCtrl = new AbortController();
    const aiTimer = setTimeout(() => aiCtrl.abort(), 30000);
    let response: Response;
    try {
      response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        signal: aiCtrl.signal,
        method: "POST",
        headers: {
          Authorization: `Bearer ${AI_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "google/gemini-2.5-pro",
          messages: [
            { role: "system", content: SYSTEM_PROMPT + FRAMEWORK_PROMPT },
            { role: "user", content: userContent },
          ],
          tools: [
            {
              type: "function",
              function: {
                name: "assess_business_fraud",
                description: "Return a structured business fraud assessment.",
                parameters: {
                  type: "object",
                  properties: {
                    risk_level: {
                      type: "string",
                      enum: RISK_LEVELS,
                      description:
                        "HIGH RISK, SUSPICIOUS, NO KNOWN THREAT DETECTED (never means legitimate), or INSUFFICIENT EVIDENCE.",
                    },
                    fraud_type: {
                      type: "string",
                      description:
                        "Specific pattern, e.g. 'Changed Supplier Banking Details', 'Business Email Compromise', 'Invoice Diversion', 'Executive Impersonation', 'Credential Phishing'. If nothing stands out use 'No known fraud pattern identified'. Never use the word 'safe' or 'legitimate'.",
                    },
                    confidence: { type: "string", enum: ["High", "Medium", "Low"] },
                    explanation: {
                      type: "string",
                      description:
                        "2-4 plain business-English sentences explaining the reasoning. Never state the request is legitimate or safe to pay.",
                    },
                    red_flags: {
                      type: "array",
                      items: { type: "string" },
                      description:
                        "2-4 short specific findings naming the exact detail observed. If nothing stands out, name what could not be confirmed.",
                      minItems: 2,
                      maxItems: 4,
                    },
                    stop: {
                      type: "array",
                      items: { type: "string" },
                      description: "1-3 short lines: exactly what must NOT be done yet.",
                      minItems: 1,
                      maxItems: 3,
                    },
                    verify: {
                      type: "array",
                      items: { type: "string" },
                      description: "1-3 short lines: exactly what must be independently confirmed.",
                      minItems: 1,
                      maxItems: 3,
                    },
                    call: {
                      type: "array",
                      items: { type: "string" },
                      description:
                        "1-3 short lines: exactly who to contact and how to find trusted contact information. Never the details contained in the request.",
                      minItems: 1,
                      maxItems: 3,
                    },
                    business_impact: {
                      type: "string",
                      description:
                        "One short line on what the business stands to lose if this proceeds unverified.",
                    },
                    verification_required: {
                      type: "boolean",
                      description: "True whenever independent verification is needed before acting.",
                    },
                    impersonation: {
                      type: "boolean",
                      description:
                        "True when someone appears to be posing as a trusted person or organisation.",
                    },
                  },
                  required: [
                    "risk_level",
                    "fraud_type",
                    "confidence",
                    "explanation",
                    "red_flags",
                    "stop",
                    "verify",
                    "call",
                    "business_impact",
                    "verification_required",
                    "impersonation",
                  ],
                  additionalProperties: false,
                },
              },
            },
          ],
          tool_choice: { type: "function", function: { name: "assess_business_fraud" } },
        }),
      });
    } catch (e) {
      logProvider("ai_gateway", e instanceof Error && e.name === "AbortError" ? "timeout" : "exception");
      return json({ error: "Could not analyze right now.", code: "ai_unavailable" }, 504);
    } finally {
      clearTimeout(aiTimer);
    }

    if (!response.ok) {
      logProvider("ai_gateway", response.status);
      if (response.status === 429) {
        return json(
          { error: "Too many checks right now. Please wait a moment and try again.", code: "ai_rate_limited" },
          429,
        );
      }
      if (response.status === 402) {
        return json(
          { error: "The service is temporarily unavailable. Please try again later.", code: "ai_credits" },
          402,
        );
      }
      return json({ error: "Could not analyze right now.", code: "ai_error" }, 500);
    }

    const data = await response.json();
    const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
    if (!toolCall) throw new Error("No assessment returned");
    const assessment = JSON.parse(toolCall.function.arguments);

    // Never let reassuring wording through, and always honour hard evidence.
    const raw = String(assessment.risk_level || "").toUpperCase().trim();
    assessment.risk_level = RISK_LEVELS.includes(raw)
      ? raw
      : raw.includes("HIGH") || raw === "SCAM"
        ? "HIGH RISK"
        : raw.includes("SAFE") || raw.includes("NO KNOWN")
          ? "NO KNOWN THREAT DETECTED"
          : "SUSPICIOUS";
    if (anyThreat) {
      assessment.risk_level = "HIGH RISK";
      assessment.confidence = "High";
    }
    if (typeof assessment.verification_required !== "boolean") {
      assessment.verification_required = true;
    }

    assessment.category = categoryKey;
    assessment.category_label = categoryLabel;
    assessment.universal_rule =
      "Never verify a suspicious request using the phone number, email address or link contained in that same request.";
    assessment.url_check = {
      checked: urls.length > 0 && (sbRes.status !== "no_key" || vtRes.status !== "no_key"),
      urls_found: urls,
      confirmed_threats: threats,
      virustotal_threats: vtThreats,
      sources: { safe_browsing: sbRes.status, virustotal: vtRes.status },
    };
    assessment.free_checks = { remaining: remainingToday, limit: FREE_DAILY_LIMIT };

    return json(assessment);
  } catch (e) {
    // Fixed message only — never the error text, stack or provider body.
    logProvider("check-business-fraud", e instanceof Error ? e.name : "exception");
    return json({ error: "Could not analyze right now.", code: "internal_error" }, 500);
  }
});