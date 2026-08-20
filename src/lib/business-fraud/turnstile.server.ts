/** Cloudflare Turnstile verification. PC_TURNSTILE_SECRET is server-only. */
import {
  allowedHostnames,
  clientIp,
  env,
  fetchWithTimeout,
  isAbort,
  type LogProvider,
} from "./runtime.server";
import { TURNSTILE_ACTION } from "./types";

const TURNSTILE_MAX_TOKEN = 2048;

export async function verifyTurnstile(
  token: unknown,
  req: Request,
  log: LogProvider,
): Promise<{ ok: true } | { ok: false; code: string }> {
  if (typeof token !== "string" || token.trim().length === 0) {
    return { ok: false, code: "turnstile_missing" };
  }
  if (token.length > TURNSTILE_MAX_TOKEN) return { ok: false, code: "turnstile_invalid" };

  const secret = env("PC_TURNSTILE_SECRET");
  // Fail closed: no secret means no verification is possible.
  if (!secret) {
    log("turnstile", "no_secret");
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
      log("turnstile", res.status);
      return { ok: false, code: "turnstile_unavailable" };
    }
    const data = await res.json();
    if (data?.success !== true) return { ok: false, code: "turnstile_invalid" };
    if (!allowedHostnames().includes(String(data?.hostname || ""))) {
      log("turnstile", "hostname_mismatch");
      return { ok: false, code: "turnstile_invalid" };
    }
    if (data?.action !== TURNSTILE_ACTION) {
      log("turnstile", "action_mismatch");
      return { ok: false, code: "turnstile_invalid" };
    }
    return { ok: true };
  } catch (e) {
    log("turnstile", isAbort(e) ? "timeout" : "exception");
    return { ok: false, code: "turnstile_unavailable" };
  }
}