/**
 * PrivaCore Business Fraud Check — server route.
 *
 * Runs server-side only (Netlify function). All provider credentials, the
 * Turnstile secret, the HMAC IP key and the Supabase service-role key are read
 * from process.env inside the handler and never reach the browser.
 *
 * It never reads or writes any Fraud Doctor state and never calls check-scam.
 */
import { createFileRoute } from "@tanstack/react-router";

import { assessBusinessFraud } from "@/lib/business-fraud/ai.server";
import {
  CATEGORY_GUIDANCE,
  CATEGORY_LABELS,
  FRAMEWORK_PROMPT,
  SYSTEM_PROMPT,
  UNIVERSAL_RULE,
} from "@/lib/business-fraud/prompt.server";
import {
  RPC_DEVICE_QUOTA,
  RPC_IP_QUOTA,
  callRpc,
  ipHash,
  nextVancouverMidnightISO,
  usageKey,
} from "@/lib/business-fraud/rate-limit.server";
import {
  corsFor,
  makeLogger,
  originAllowed,
} from "@/lib/business-fraud/runtime.server";
import {
  checkSafeBrowsing,
  checkVirusTotal,
  extractUrls,
} from "@/lib/business-fraud/threat-intel.server";
import { verifyTurnstile } from "@/lib/business-fraud/turnstile.server";
import {
  FREE_DAILY_LIMIT,
  IP_BURST_LIMIT,
  IP_DAILY_LIMIT,
  MAX_BODY_BYTES,
  MAX_TEXT_CHARS,
  RISK_LEVELS,
} from "@/lib/business-fraud/types";
import { validateImage } from "@/lib/business-fraud/validate.server";

async function handlePost({ request }: { request: Request }): Promise<Response> {
  const origin = request.headers.get("origin");
  const corsHeaders = corsFor(origin);
  const correlationId = crypto.randomUUID().slice(0, 8);
  const log = makeLogger(correlationId);

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (!originAllowed(origin)) {
    return json({ error: "not_allowed", code: "origin_not_allowed" }, 403);
  }

  try {
    const declaredLength = Number(request.headers.get("content-length") || "0");
    if (declaredLength > MAX_BODY_BYTES) {
      return json({ error: "too_large", code: "body_too_large" }, 413);
    }
    const rawBody = await request.text();
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

    const categoryKey =
      typeof category === "string" && CATEGORY_LABELS[category] ? category : "other";
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
    const ts = await verifyTurnstile(turnstile_token, request, log);
    if (!ts.ok) return json({ error: "turnstile_failed", code: ts.code }, 403);

    // 2. PrivaCore-only usage ceilings: device allowance, then network ceilings.
    const deviceGate = await callRpc(
      RPC_DEVICE_QUOTA,
      { _device_id: usageKey(device_id, request), _limit: FREE_DAILY_LIMIT },
      log,
    );
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

    const hash = await ipHash(request);
    const netGate = hash
      ? await callRpc(
          RPC_IP_QUOTA,
          { _ip_hash: hash, _daily_limit: IP_DAILY_LIMIT, _burst_limit: IP_BURST_LIMIT },
          log,
        )
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

    // 3. URL reputation (server-side, lookup only, in parallel).
    const urls = hasMessage ? extractUrls(message) : [];
    const [sbRes, vtRes] = await Promise.all([
      checkSafeBrowsing(urls, log),
      checkVirusTotal(urls, log),
    ]);
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
        if (sbRes.status === "timeout" || sbRes.status === "error") {
          downNames.push("Google Safe Browsing");
        }
        if (vtRes.status === "timeout" || vtRes.status === "error") downNames.push("VirusTotal");
        urlEvidence = `\n\nURL REPUTATION RESULTS: ${downNames.join(" and ")} did not respond in time. Do NOT suggest the link is fine on that basis. Judge the domain, wording and business process instead.`;
      } else {
        urlEvidence = `\n\nURL REPUTATION RESULTS: no known threat was found for the URL(s) by Google Safe Browsing or VirusTotal. That means only that no known threat is on record — it does NOT prove the site, sender or request is legitimate. Fraudulent business domains are usually new, clean, or hosted on reputable infrastructure. Continue analysing domain spelling, page purpose and the business process.`;
      }
    }

    const contextLine = `The user selected the check type: "${categoryLabel}". ${categoryGuidance}`;
    const textPart = hasMessage
      ? `${contextLine}\n\nAssess the following business content:\n\n"""${message.slice(0, MAX_TEXT_CHARS)}"""${urlEvidence}`
      : `${contextLine}\n\nAssess the attached screenshot. Read every visible detail (sender address, reply-to, domain, banking details, amounts, buttons, URLs). If the image is unreadable or contains too little to assess, return "INSUFFICIENT EVIDENCE".${urlEvidence}`;

    const userContent: any[] = [{ type: "text", text: textPart }];
    if (hasImage) userContent.push({ type: "image_url", image_url: { url: image } });

    const ai = await assessBusinessFraud(SYSTEM_PROMPT + FRAMEWORK_PROMPT, userContent, log);
    if (!ai.ok) {
      const messages: Record<string, string> = {
        ai_rate_limited: "Too many checks right now. Please wait a moment and try again.",
        ai_credits: "The service is temporarily unavailable. Please try again later.",
      };
      return json(
        { error: messages[ai.code] ?? "Could not analyze right now.", code: ai.code },
        ai.status,
      );
    }
    const assessment = ai.assessment;

    // Never let reassuring wording through, and always honour hard evidence.
    const raw = String(assessment['risk_level'] || "").toUpperCase().trim();
    assessment['risk_level'] = (RISK_LEVELS as readonly string[]).includes(raw)
      ? raw
      : raw.includes("HIGH") || raw === "SCAM"
        ? "HIGH RISK"
        : raw.includes("SAFE") || raw.includes("NO KNOWN")
          ? "NO KNOWN THREAT DETECTED"
          : "SUSPICIOUS";
    if (anyThreat) {
      assessment['risk_level'] = "HIGH RISK";
      assessment['confidence'] = "High";
    }
    if (typeof assessment['verification_required'] !== "boolean") {
      assessment['verification_required'] = true;
    }

    assessment['category'] = categoryKey;
    assessment['category_label'] = categoryLabel;
    assessment['universal_rule'] = UNIVERSAL_RULE;
    assessment['url_check'] = {
      checked: urls.length > 0 && (sbRes.status !== "no_key" || vtRes.status !== "no_key"),
      urls_found: urls,
      confirmed_threats: threats,
      virustotal_threats: vtThreats,
      sources: { safe_browsing: sbRes.status, virustotal: vtRes.status },
    };
    assessment['free_checks'] = { remaining: remainingToday, limit: FREE_DAILY_LIMIT };

    return json(assessment);
  } catch (e) {
    // Fixed message only — never the error text, stack or provider body.
    log("check-business-fraud", e instanceof Error ? e.name : "exception");
    return json({ error: "Could not analyze right now.", code: "internal_error" }, 500);
  }
}

export const Route = createFileRoute("/api/public/check-business-fraud")({
  server: {
    handlers: {
      OPTIONS: async ({ request }) =>
        new Response(null, { status: 204, headers: corsFor(request.headers.get("origin")) }),
      POST: handlePost,
    },
  },
});