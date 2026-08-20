/**
 * Client-side contract for the PrivaCore `check-business-fraud` edge function.
 * Only public VITE_* values are read here; no secret ever reaches the browser.
 */

export const RISK_LEVELS = [
  "HIGH RISK",
  "SUSPICIOUS",
  "NO KNOWN THREAT DETECTED",
  "INSUFFICIENT EVIDENCE",
] as const;

export type RiskLevel = (typeof RISK_LEVELS)[number];

export type Assessment = {
  risk_level: RiskLevel;
  fraud_type: string;
  confidence: "High" | "Medium" | "Low";
  explanation: string;
  red_flags: string[];
  stop: string[];
  verify: string[];
  call: string[];
  business_impact: string;
  verification_required: boolean;
  impersonation: boolean;
  category: string;
  category_label: string;
  universal_rule: string;
  url_check?: {
    checked: boolean;
    urls_found: string[];
    confirmed_threats: Record<string, string>;
    virustotal_threats: Record<string, string>;
  };
  free_checks?: { remaining: number; limit: number };
};

export const CATEGORIES = [
  { value: "payment_invoice", label: "Payment or invoice" },
  { value: "banking_change", label: "Banking information change" },
  { value: "supplier", label: "Supplier or subcontractor" },
  { value: "email_message", label: "Email or message" },
  { value: "website_link", label: "Website or link" },
  { value: "executive_request", label: "Executive or owner request" },
  { value: "customer_payment", label: "Customer payment" },
  { value: "government_grant", label: "Government / grant / rebate" },
  { value: "other", label: "Something else" },
] as const;

export const MAX_TEXT_CHARS = 6000;
export const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

export const SUPABASE_URL = (import.meta.env['VITE_PC_SUPABASE_URL'] as string | undefined) ?? "";
export const SUPABASE_ANON_KEY =
  (import.meta.env['VITE_PC_SUPABASE_ANON_KEY'] as string | undefined) ?? "";
export const TURNSTILE_SITE_KEY =
  (import.meta.env['VITE_PC_TURNSTILE_SITE_KEY'] as string | undefined) ?? "";

export const FUNCTION_URL = SUPABASE_URL
  ? `${SUPABASE_URL.replace(/\/+$/, "")}/functions/v1/check-business-fraud`
  : "";

/** Stable, non-identifying local id used only for the daily allowance. */
export function getDeviceId(): string {
  const KEY = "pc_business_device_id";
  try {
    const existing = localStorage.getItem(KEY);
    if (existing && existing.length >= 8) return existing;
    const fresh = crypto.randomUUID();
    localStorage.setItem(KEY, fresh);
    return fresh;
  } catch {
    return "";
  }
}

export type CheckOutcome =
  | { kind: "result"; assessment: Assessment }
  | { kind: "limit"; message: string }
  | { kind: "error"; message: string };

const FRIENDLY: Record<string, string> = {
  empty_input: "Paste the text, link or screenshot you want checked.",
  text_too_long: "That's too long to check. Paste the most important part.",
  body_too_large: "That file is too large. Use an image under 8 MB.",
  image_too_large: "That image is too large. Use an image under 8 MB.",
  image_type: "Use a PNG, JPEG or WebP screenshot.",
  image_signature: "That file doesn't look like a real image.",
  image_mismatch: "That file doesn't look like a real image.",
  image_invalid: "That screenshot couldn't be read. Try taking it again.",
  turnstile_missing: "Please complete the human check and try again.",
  turnstile_invalid: "The human check failed. Please refresh and try again.",
  turnstile_unavailable: "The human check is unavailable right now. Please try again shortly.",
  origin_not_allowed: "This checker isn't available from this address.",
  quota_unavailable: "The service is busy right now. Please try again in a moment.",
  ai_rate_limited: "Too many checks right now. Please wait a moment and try again.",
  ai_credits: "The service is temporarily unavailable. Please try again later.",
  ai_unavailable: "Could not analyze right now. Please try again shortly.",
};

export async function runCheck(input: {
  message: string;
  image: string | null;
  category: string;
  turnstileToken: string;
}): Promise<CheckOutcome> {
  if (!FUNCTION_URL) {
    return { kind: "error", message: "The checker isn't configured yet. Please try again later." };
  }

  let res: Response;
  try {
    res = await fetch(FUNCTION_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(SUPABASE_ANON_KEY
          ? { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${SUPABASE_ANON_KEY}` }
          : {}),
      },
      body: JSON.stringify({
        message: input.message,
        image: input.image,
        category: input.category,
        device_id: getDeviceId(),
        turnstile_token: input.turnstileToken,
      }),
    });
  } catch {
    return { kind: "error", message: "Couldn't reach the checker. Check your connection and try again." };
  }

  let data: any = null;
  try {
    data = await res.json();
  } catch {
    /* fall through to the generic message */
  }

  if (res.ok && data?.risk_level) return { kind: "result", assessment: data as Assessment };

  if (data?.limit_reached) {
    return {
      kind: "limit",
      message: `You've used all ${data.limit} free checks for today. Your checks reset after midnight Pacific time.`,
    };
  }
  if (data?.network_limit_reached) {
    return {
      kind: "limit",
      message:
        data.reason === "burst"
          ? "That's a lot of checks in a short time. Please wait a few minutes and try again."
          : "This network has reached today's check limit. Please try again tomorrow.",
    };
  }

  const code = typeof data?.code === "string" ? data.code : "";
  return {
    kind: "error",
    message: FRIENDLY[code] ?? "Could not analyze right now. Please try again shortly.",
  };
}