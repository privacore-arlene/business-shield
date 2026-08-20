/**
 * Server-only primitives shared by the check-business-fraud route:
 * env access, origin allow-list, privacy-safe logging and timed fetch.
 *
 * Every process.env read happens inside a function so it resolves at request
 * time (Netlify injects environment variables per invocation).
 */

export const PRODUCTION_ORIGIN = "https://check.privacoregroup.com";

/** PrivaCore-specific credential first, generic fallback second. */
export function env(name: string, fallback?: string): string {
  const direct = process.env[name];
  if (direct && direct.trim()) return direct.trim();
  if (fallback) {
    const alt = process.env[fallback];
    if (alt && alt.trim()) return alt.trim();
  }
  return "";
}

/** Exact browser origins allowed to call the route. Never a wildcard. */
export function allowedOrigins(): string[] {
  const extra = (env("PC_ALLOWED_ORIGINS", "PC_EXTRA_ALLOWED_ORIGINS") || "")
    .split(",")
    .map((o) => o.trim())
    .filter((o) => /^https?:\/\/[^*\s]+$/.test(o));
  return [PRODUCTION_ORIGIN, ...extra, ...localhostOrigins()];
}

/**
 * Localhost is never allowed implicitly. It requires an explicit opt-in
 * (`PC_ALLOW_LOCALHOST_ORIGINS=true`) AND a non-production NODE_ENV, so a
 * missing or mis-set NODE_ENV alone can never open localhost in production.
 */
function localhostOrigins(): string[] {
  const optIn = env("PC_ALLOW_LOCALHOST_ORIGINS").toLowerCase() === "true";
  if (!optIn) return [];
  const nodeEnv = (process.env["NODE_ENV"] || "").trim().toLowerCase();
  if (nodeEnv !== "development" && nodeEnv !== "test") return [];
  return ["http://localhost:8080", "http://127.0.0.1:8080"];
}

/** Hostnames Turnstile tokens may be minted on. */
export function allowedHostnames(): string[] {
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

/**
 * The route is same-origin in production, so a missing Origin header (direct
 * navigation, some same-origin fetches) is accepted; a foreign Origin is not.
 */
export function originAllowed(origin: string | null): boolean {
  return !origin || allowedOrigins().includes(origin);
}

export function corsFor(origin: string | null): Record<string, string> {
  const headers: Record<string, string> = {
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    Vary: "Origin",
    "Cache-Control": "no-store",
  };
  if (origin && allowedOrigins().includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return headers;
}

/**
 * Privacy-safe operational logging: provider name, status and a correlation
 * id only. Never a URL, message, screenshot, prompt or model response.
 */
export function makeLogger(correlationId: string) {
  return (provider: string, status: string | number): void => {
    console.error(`app=privacore provider=${provider} status=${status} cid=${correlationId}`);
  };
}

export type LogProvider = ReturnType<typeof makeLogger>;

export async function fetchWithTimeout(
  url: string,
  opts: RequestInit,
  ms: number,
): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

export function isAbort(e: unknown): boolean {
  return e instanceof Error && e.name === "AbortError";
}

/** First client IP as seen by Netlify's edge. */
export function clientIp(req: Request): string {
  const direct = req.headers.get("x-nf-client-connection-ip");
  if (direct) return direct.trim();
  const cf = req.headers.get("cf-connecting-ip");
  if (cf) return cf.trim();
  return (req.headers.get("x-forwarded-for") || "").split(",")[0]?.trim() ?? "";
}