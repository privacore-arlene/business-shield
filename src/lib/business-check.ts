/**
 * Client-side contract for the PrivaCore check-business-fraud server function.
 * The route is same-origin, so the browser sends no credentials at all; the
 * only public value read here is the Turnstile site key.
 */
import {
  CATEGORIES,
  MAX_IMAGE_BYTES,
  MAX_TEXT_CHARS,
  RISK_LEVELS,
  type Assessment,
  type RiskLevel,
} from "./business-fraud/types";

export { CATEGORIES, MAX_IMAGE_BYTES, MAX_TEXT_CHARS, RISK_LEVELS };
export type { Assessment, RiskLevel };

export const TURNSTILE_SITE_KEY =
  (import.meta.env['VITE_PC_TURNSTILE_SITE_KEY'] as string | undefined) ?? "";

/** Same-origin server route; no key, no cross-origin request. */
export const FUNCTION_URL = "/api/public/check-business-fraud";

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
  ai_unavailable: "Could not reach the analysis service. Please try again shortly.",
  ai_timeout: "That check took too long to analyse. Try again with a shorter excerpt.",
  ai_not_configured:
    "The checker isn't finished being set up: the AI key (PC_AI_API_KEY) is missing on the server.",
  ai_auth: "The AI key on the server was rejected. Please check PC_AI_API_KEY.",
  ai_request:
    "The AI service rejected the request (model or endpoint setting). Please check PC_AI_MODEL / PC_AI_BASE_URL.",
  ai_error: "The analysis service returned an error. Please try again shortly.",
};

export async function runCheck(input: {
  message: string;
  image: string | null;
  category: string;
  turnstileToken: string;
}): Promise<CheckOutcome> {
  let res: Response;
  try {
    res = await fetch(FUNCTION_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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