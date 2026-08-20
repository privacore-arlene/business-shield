/**
 * PrivaCore-only rate limiting against the existing pc_business_* RPCs.
 * Uses the Supabase service-role key server-side; it never leaves this module.
 */
import { clientIp, env, fetchWithTimeout, isAbort, type LogProvider } from "./runtime.server";

export const RPC_DEVICE_QUOTA = "pc_consume_business_daily_check";
export const RPC_IP_QUOTA = "pc_consume_business_ip_check";

/**
 * Pseudonymous, domain-separated HMAC of the caller IP. The raw IP is never
 * stored, logged, returned or forwarded. The domain separator is PrivaCore
 * specific, so business hashes can never collide with Fraud Doctor records.
 */
export async function ipHash(req: Request): Promise<string | null> {
  const ip = clientIp(req);
  if (!ip) return null;
  const keyMaterial = env("PC_IP_HASH_KEY", "PC_SUPABASE_SERVICE_ROLE_KEY");
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

export async function callRpc(
  name: string,
  body: unknown,
  log: LogProvider,
): Promise<any | "unavailable"> {
  const url = env("PC_SUPABASE_URL");
  const serviceKey = env("PC_SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) {
    log(name, "no_credentials");
    return "unavailable";
  }
  try {
    const res = await fetchWithTimeout(
      `${url.replace(/\/+$/, "")}/rest/v1/rpc/${name}`,
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
      log(name, res.status);
      return "unavailable";
    }
    const rows = await res.json();
    const row = Array.isArray(rows) ? rows[0] : rows;
    return row ?? "unavailable";
  } catch (e) {
    log(name, isAbort(e) ? "timeout" : "exception");
    return "unavailable";
  }
}

/** Device id is one signal only; the network ceilings are the backstop. */
export function usageKey(deviceId: unknown, req: Request): string {
  const id = typeof deviceId === "string" ? deviceId.trim().slice(0, 100) : "";
  if (id.length >= 8) return `dev:${id}`;
  const ip = clientIp(req);
  return `ip:${ip || "unknown"}`;
}

export function nextVancouverMidnightISO(): string {
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