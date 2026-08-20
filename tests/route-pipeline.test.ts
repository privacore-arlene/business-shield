/**
 * End-to-end tests of the /api/public/check-business-fraud handler with every
 * external provider stubbed. No paid API call is ever made.
 */
import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { Route } from "../src/routes/api/public/check-business-fraud";

const POST: any = (Route as any).options.server.handlers.POST;
const realFetch = globalThis.fetch;
const ORIGIN = "https://check.privacoregroup.com";

function post(body: unknown, origin: string | null = ORIGIN) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-nf-client-connection-ip": "203.0.113.9",
  };
  if (origin) headers["origin"] = origin;
  return POST({
    request: new Request(`${ORIGIN}/api/public/check-business-fraud`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    }),
  }) as Promise<Response>;
}

const AI_ASSESSMENT = {
  risk_level: "NO KNOWN THREAT DETECTED",
  fraud_type: "No known fraud pattern identified",
  confidence: "Low",
  explanation: "e",
  red_flags: ["a", "b"],
  stop: ["s"],
  verify: ["v"],
  call: ["c"],
  business_impact: "b",
  verification_required: true,
  impersonation: false,
};

/** Router that answers each provider from a local table. */
function stubProviders(opts: { webRiskThreat?: boolean; quotaOk?: boolean } = {}) {
  const { webRiskThreat = false, quotaOk = true } = opts;
  globalThis.fetch = (async (u: any) => {
    const url = String(u);
    if (url.includes("challenges.cloudflare.com")) {
      return Response.json({
        success: true,
        hostname: "check.privacoregroup.com",
        action: "check-business-fraud",
      });
    }
    if (url.includes("/rpc/")) {
      if (!quotaOk) return new Response("down", { status: 500 });
      return Response.json([{ allowed: true, remaining: 4, used: 1, reason: "", resets_at: "" }]);
    }
    if (url.includes("webrisk.googleapis.com")) {
      return Response.json(webRiskThreat ? { threat: { threatTypes: ["MALWARE"] } } : {});
    }
    if (url.includes("virustotal.com")) return new Response("", { status: 404 });
    if (url.includes("chat/completions")) {
      return Response.json({
        choices: [
          { message: { tool_calls: [{ function: { arguments: JSON.stringify(AI_ASSESSMENT) } }] } },
        ],
      });
    }
    throw new Error(`unexpected outbound call: ${url}`);
  }) as any;
}

beforeEach(() => {
  process.env["PC_TURNSTILE_SECRET"] = "ts";
  process.env["PC_SUPABASE_URL"] = "https://proj.supabase.co";
  process.env["PC_SUPABASE_SERVICE_ROLE_KEY"] = "svc";
  process.env["PC_IP_HASH_KEY"] = "hash-key";
  process.env["PC_AI_API_KEY"] = "gem";
  process.env["PC_GOOGLE_WEB_RISK_API_KEY"] = "wr";
  delete process.env["PC_VIRUSTOTAL_API_KEY"];
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

const base = { message: "Please update our banking details", category: "banking_change", device_id: "device-1234", turnstile_token: "tok" };

test("rejects a foreign origin before any provider call", async () => {
  globalThis.fetch = (async () => {
    throw new Error("should not be called");
  }) as any;
  const res = await post(base, "https://evil.example.com");
  expect(res.status).toBe(403);
  expect((await res.json()).code).toBe("origin_not_allowed");
});

test("rejects a missing Turnstile token before any provider call", async () => {
  globalThis.fetch = (async () => {
    throw new Error("should not be called");
  }) as any;
  const res = await post({ ...base, turnstile_token: undefined });
  expect(res.status).toBe(403);
  expect((await res.json()).code).toBe("turnstile_missing");
});

test("happy path returns a STOP/VERIFY/CALL assessment and no secrets", async () => {
  stubProviders();
  const res = await post(base);
  expect(res.status).toBe(200);
  const body = await res.json();
  expect(body.risk_level).toBe("NO KNOWN THREAT DETECTED");
  expect(Array.isArray(body.stop) && Array.isArray(body.verify) && Array.isArray(body.call)).toBe(true);
  expect(body.free_checks).toEqual({ remaining: 4, limit: 5 });
  const raw = JSON.stringify(body);
  for (const s of ["gem", "svc", "ts", "hash-key", "wr", "203.0.113.9"]) {
    expect(raw.includes(s === "ts" ? '"ts"' : s)).toBe(false);
  }
});

test("a confirmed Web Risk threat overrides the AI verdict to HIGH RISK", async () => {
  stubProviders({ webRiskThreat: true });
  const res = await post({ ...base, message: "pay via https://bad.example/invoice" });
  const body = await res.json();
  expect(body.risk_level).toBe("HIGH RISK");
  expect(body.confidence).toBe("High");
  expect(body.url_check.confirmed_threats["https://bad.example/invoice"]).toBe("MALWARE");
});

test("quota RPC failure fails closed with 503", async () => {
  stubProviders({ quotaOk: false });
  const res = await post(base);
  expect(res.status).toBe(503);
  expect((await res.json()).code).toBe("quota_unavailable");
});

test("VirusTotal is skipped entirely when no key is configured", async () => {
  const calls: string[] = [];
  stubProviders();
  const inner = globalThis.fetch;
  globalThis.fetch = (async (u: any, i: any) => {
    calls.push(String(u));
    return (inner as any)(u, i);
  }) as any;
  await post({ ...base, message: "check https://example.com/invoice" });
  expect(calls.some((c) => c.includes("virustotal.com"))).toBe(false);
  expect(calls.some((c) => c.includes("webrisk.googleapis.com"))).toBe(true);
});

test("AI outage returns an error state, never an invented verdict", async () => {
  stubProviders();
  const inner = globalThis.fetch;
  globalThis.fetch = (async (u: any, i: any) =>
    String(u).includes("chat/completions")
      ? new Response("down", { status: 500 })
      : (inner as any)(u, i)) as any;
  const res = await post(base);
  expect(res.status).toBe(500);
  const body = await res.json();
  expect(body.code).toBe("ai_error");
  expect(body.risk_level).toBeUndefined();
});

test("empty submission is rejected before any provider call", async () => {
  globalThis.fetch = (async () => {
    throw new Error("should not be called");
  }) as any;
  const res = await post({ ...base, message: "" });
  expect(res.status).toBe(400);
  expect((await res.json()).code).toBe("empty_input");
});

test("a bad screenshot is rejected before any provider call", async () => {
  globalThis.fetch = (async () => {
    throw new Error("should not be called");
  }) as any;
  const res = await post({ ...base, message: "", image: "data:image/png;base64,QUJD" });
  expect(res.status).toBe(400);
  expect((await res.json()).code).toBe("image_signature");
});

test("no submitted content is logged", async () => {
  stubProviders({ quotaOk: false });
  const lines: string[] = [];
  const orig = console.error;
  console.error = (m: any) => lines.push(String(m));
  await post({ ...base, message: "secret invoice 12345 https://private.example" });
  console.error = orig;
  expect(lines.join("\n")).not.toContain("private.example");
  expect(lines.join("\n")).not.toContain("12345");
});
