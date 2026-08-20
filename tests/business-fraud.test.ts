/**
 * Offline safety tests for the PrivaCore Business Fraud Check server modules.
 * No paid provider is ever called: global fetch is stubbed in every case.
 */
import { describe, expect, test, beforeEach, afterEach } from "bun:test";

import {
  allowedOrigins,
  corsFor,
  makeLogger,
  originAllowed,
  clientIp,
} from "../src/lib/business-fraud/runtime.server";
import { verifyTurnstile } from "../src/lib/business-fraud/turnstile.server";
import { validateImage } from "../src/lib/business-fraud/validate.server";
import {
  checkVirusTotal,
  checkWebRisk,
  extractUrls,
} from "../src/lib/business-fraud/threat-intel.server";
import { callRpc, ipHash, usageKey } from "../src/lib/business-fraud/rate-limit.server";
import { assessBusinessFraud } from "../src/lib/business-fraud/ai.server";

const log = makeLogger("test");
const realFetch = globalThis.fetch;
const snapshot = { ...process.env };

function reqWith(headers: Record<string, string> = {}) {
  return new Request("https://check.privacoregroup.com/api/public/check-business-fraud", {
    method: "POST",
    headers,
  });
}

beforeEach(() => {
  for (const k of Object.keys(process.env)) if (k.startsWith("PC_")) delete process.env[k];
});
afterEach(() => {
  globalThis.fetch = realFetch;
  for (const k of Object.keys(process.env)) if (k.startsWith("PC_")) delete process.env[k];
  for (const [k, v] of Object.entries(snapshot)) if (k.startsWith("PC_")) process.env[k] = v as string;
});

describe("origin allow-list", () => {
  test("production origin is always allowed", () => {
    expect(allowedOrigins()).toContain("https://check.privacoregroup.com");
    expect(originAllowed("https://check.privacoregroup.com")).toBe(true);
  });
  test("unknown origin is rejected", () => {
    expect(originAllowed("https://evil.example.com")).toBe(false);
    expect(corsFor("https://evil.example.com")["Access-Control-Allow-Origin"]).toBeUndefined();
  });
  test("localhost is rejected in production even with opt-in", () => {
    process.env["NODE_ENV"] = "production";
    process.env["PC_ALLOW_LOCALHOST_ORIGINS"] = "true";
    expect(originAllowed("http://localhost:8080")).toBe(false);
  });
  test("localhost is rejected without opt-in", () => {
    process.env["NODE_ENV"] = "development";
    expect(originAllowed("http://localhost:8080")).toBe(false);
  });
  test("no wildcard is ever emitted", () => {
    expect(JSON.stringify(corsFor("*"))).not.toContain('"Access-Control-Allow-Origin":"*"');
  });
});

describe("turnstile fails closed", () => {
  test("missing token", async () => {
    expect(await verifyTurnstile(undefined, reqWith(), log)).toEqual({
      ok: false,
      code: "turnstile_missing",
    });
  });
  test("missing secret -> unavailable, no network call", async () => {
    let called = false;
    globalThis.fetch = (async () => {
      called = true;
      return new Response("{}");
    }) as any;
    const r = await verifyTurnstile("tok", reqWith(), log);
    expect(r).toEqual({ ok: false, code: "turnstile_unavailable" });
    expect(called).toBe(false);
  });
  test("hostname mismatch rejected", async () => {
    process.env["PC_TURNSTILE_SECRET"] = "s";
    globalThis.fetch = (async () =>
      Response.json({ success: true, hostname: "evil.com", action: "check-business-fraud" })) as any;
    expect(await verifyTurnstile("tok", reqWith(), log)).toEqual({
      ok: false,
      code: "turnstile_invalid",
    });
  });
  test("action mismatch rejected", async () => {
    process.env["PC_TURNSTILE_SECRET"] = "s";
    globalThis.fetch = (async () =>
      Response.json({
        success: true,
        hostname: "check.privacoregroup.com",
        action: "other",
      })) as any;
    expect(await verifyTurnstile("tok", reqWith(), log)).toEqual({
      ok: false,
      code: "turnstile_invalid",
    });
  });
  test("valid token accepted and secret is not echoed to the client", async () => {
    process.env["PC_TURNSTILE_SECRET"] = "s3cr3t";
    let body = "";
    globalThis.fetch = (async (_u: any, init: any) => {
      body = String(init.body);
      return Response.json({
        success: true,
        hostname: "check.privacoregroup.com",
        action: "check-business-fraud",
      });
    }) as any;
    expect(await verifyTurnstile("tok", reqWith(), log)).toEqual({ ok: true });
    expect(body).toContain("secret=s3cr3t"); // sent to Cloudflare only
  });
  test("provider outage fails closed", async () => {
    process.env["PC_TURNSTILE_SECRET"] = "s";
    globalThis.fetch = (async () => new Response("nope", { status: 500 })) as any;
    expect(await verifyTurnstile("tok", reqWith(), log)).toEqual({
      ok: false,
      code: "turnstile_unavailable",
    });
  });
});

describe("ip hashing", () => {
  const ipReq = reqWith({ "x-nf-client-connection-ip": "203.0.113.9" });
  test("hash is deterministic, hex, and never contains the raw IP", async () => {
    process.env["PC_IP_HASH_KEY"] = "unit-test-key";
    const a = await ipHash(ipReq);
    const b = await ipHash(ipReq);
    expect(a).toBe(b!);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toContain("203.0.113.9");
  });
  test("different keys produce different hashes", async () => {
    process.env["PC_IP_HASH_KEY"] = "k1";
    const a = await ipHash(ipReq);
    process.env["PC_IP_HASH_KEY"] = "k2";
    expect(await ipHash(ipReq)).not.toBe(a!);
  });
  test("no key material -> null (no unsalted hash)", async () => {
    expect(await ipHash(ipReq)).toBeNull();
  });
  test("usage key prefers the device id over the IP", () => {
    expect(usageKey("abcdefgh12", ipReq)).toBe("dev:abcdefgh12");
    expect(usageKey("x", ipReq)).toBe("ip:203.0.113.9");
  });
  test("clientIp reads Netlify's edge header", () => {
    expect(clientIp(ipReq)).toBe("203.0.113.9");
  });
});

describe("rate-limit RPCs", () => {
  test("no credentials -> unavailable (fails closed)", async () => {
    expect(await callRpc("pc_consume_business_daily_check", {}, log)).toBe("unavailable");
  });
  test("calls the correct PostgREST RPC with service-role headers", async () => {
    process.env["PC_SUPABASE_URL"] = "https://proj.supabase.co";
    process.env["PC_SUPABASE_SERVICE_ROLE_KEY"] = "svc";
    let seen: any = {};
    globalThis.fetch = (async (u: any, init: any) => {
      seen = { url: String(u), init };
      return Response.json([{ allowed: true, remaining: 4, used: 1 }]);
    }) as any;
    const row = await callRpc(
      "pc_consume_business_daily_check",
      { _device_id: "dev:x", _limit: 5 },
      log,
    );
    expect(seen.url).toBe(
      "https://proj.supabase.co/rest/v1/rpc/pc_consume_business_daily_check",
    );
    expect(seen.init.headers.apikey).toBe("svc");
    expect(seen.init.headers.Authorization).toBe("Bearer svc");
    expect(JSON.parse(seen.init.body)).toEqual({ _device_id: "dev:x", _limit: 5 });
    expect(row.allowed).toBe(true);
  });
  test("RPC error -> unavailable (fails closed)", async () => {
    process.env["PC_SUPABASE_URL"] = "https://proj.supabase.co";
    process.env["PC_SUPABASE_SERVICE_ROLE_KEY"] = "svc";
    globalThis.fetch = (async () => new Response("boom", { status: 500 })) as any;
    expect(await callRpc("pc_consume_business_ip_check", {}, log)).toBe("unavailable");
  });
});

describe("threat intel", () => {
  test("extractUrls normalises, dedupes and caps at 5", () => {
    const urls = extractUrls(
      "see www.a.com and https://b.com, https://b.com https://c.com https://d.com https://e.com https://f.com https://g.com",
    );
    expect(urls[0]).toBe("http://www.a.com");
    expect(urls.filter((u) => u === "https://b.com").length).toBe(1);
    expect(urls.length).toBeLessThanOrEqual(5);
  });
  test("Web Risk uses uris:search with the key and threat types", async () => {
    process.env["PC_GOOGLE_WEB_RISK_API_KEY"] = "wr-key";
    let url = "";
    globalThis.fetch = (async (u: any) => {
      url = String(u);
      return Response.json({});
    }) as any;
    const r = await checkWebRisk(["https://bad.example"], log);
    expect(url).toStartWith("https://webrisk.googleapis.com/v1/uris:search?");
    expect(url).toContain("key=wr-key");
    expect(url).toContain("uri=https%3A%2F%2Fbad.example");
    expect(url).toContain("threatTypes=SOCIAL_ENGINEERING");
    expect(r.status).toBe("ok"); // no `threat` field == no KNOWN threat
    expect(r.threats).toEqual({});
  });
  test("Web Risk threat is surfaced", async () => {
    process.env["PC_GOOGLE_WEB_RISK_API_KEY"] = "wr-key";
    globalThis.fetch = (async () =>
      Response.json({ threat: { threatTypes: ["SOCIAL_ENGINEERING"] } })) as any;
    const r = await checkWebRisk(["https://bad.example"], log);
    expect(r.status).toBe("threat");
    expect(r.threats["https://bad.example"]).toBe("SOCIAL_ENGINEERING");
  });
  test("Web Risk outage is reported as error, never as clean", async () => {
    process.env["PC_GOOGLE_WEB_RISK_API_KEY"] = "wr-key";
    globalThis.fetch = (async () => new Response("x", { status: 503 })) as any;
    expect((await checkWebRisk(["https://x.example"], log)).status).toBe("error");
  });
  test("Web Risk without a key makes no call", async () => {
    let called = false;
    globalThis.fetch = (async () => {
      called = true;
      return Response.json({});
    }) as any;
    expect((await checkWebRisk(["https://x.example"], log)).status).toBe("no_key");
    expect(called).toBe(false);
  });
  test("VirusTotal without a key makes no call", async () => {
    let called = false;
    globalThis.fetch = (async () => {
      called = true;
      return Response.json({});
    }) as any;
    expect((await checkVirusTotal(["https://x.example"], log)).status).toBe("no_key");
    expect(called).toBe(false);
  });
  test("VirusTotal is lookup-only: GET on the cached URL id, never a submission", async () => {
    process.env["PC_VIRUSTOTAL_API_KEY"] = "vt";
    const calls: any[] = [];
    globalThis.fetch = (async (u: any, init: any) => {
      calls.push({ url: String(u), method: init?.method });
      return Response.json({
        data: { attributes: { last_analysis_stats: { malicious: 3, harmless: 60 } } },
      });
    }) as any;
    const r = await checkVirusTotal(["https://bad.example"], log);
    expect(calls.length).toBe(1);
    expect(calls[0].method).toBeUndefined(); // GET
    expect(calls[0].url).toStartWith("https://www.virustotal.com/api/v3/urls/");
    expect(calls[0].url).not.toContain("/urls?"); // no POST-style submission endpoint
    expect(r.status).toBe("threat");
  });
  test("VirusTotal 404 (unknown URL) is not treated as a threat or a failure", async () => {
    process.env["PC_VIRUSTOTAL_API_KEY"] = "vt";
    globalThis.fetch = (async () => new Response("", { status: 404 })) as any;
    const r = await checkVirusTotal(["https://unknown.example"], log);
    expect(r.status).toBe("ok");
    expect(r.threats).toEqual({});
  });
});

describe("AI boundary", () => {
  test("no key -> ai_unavailable, no request made, no verdict invented", async () => {
    let called = false;
    globalThis.fetch = (async () => {
      called = true;
      return Response.json({});
    }) as any;
    const r = await assessBusinessFraud("sys", [{ type: "text", text: "hi" }], log);
    expect(called).toBe(false);
    expect(r).toEqual({ ok: false, code: "ai_unavailable", status: 503 });
  });
  test("provider 429/402/500 surface as errors, never as an assessment", async () => {
    process.env["PC_AI_API_KEY"] = "k";
    for (const [status, code] of [
      [429, "ai_rate_limited"],
      [402, "ai_credits"],
      [500, "ai_error"],
    ] as const) {
      globalThis.fetch = (async () => new Response("x", { status })) as any;
      const r = await assessBusinessFraud("sys", [], log);
      expect(r.ok).toBe(false);
      expect((r as any).code).toBe(code);
    }
  });
  test("malformed provider output -> ai_error, not a fabricated verdict", async () => {
    process.env["PC_AI_API_KEY"] = "k";
    globalThis.fetch = (async () => Response.json({ choices: [{ message: {} }] })) as any;
    const r = await assessBusinessFraud("sys", [], log);
    expect(r).toEqual({ ok: false, code: "ai_error", status: 500 });
  });
  test("key is sent only to the provider endpoint", async () => {
    process.env["PC_AI_API_KEY"] = "gem-key";
    let seen: any = {};
    globalThis.fetch = (async (u: any, init: any) => {
      seen = { url: String(u), auth: init.headers.Authorization };
      return Response.json({
        choices: [
          { message: { tool_calls: [{ function: { arguments: '{"risk_level":"SUSPICIOUS"}' } }] } },
        ],
      });
    }) as any;
    const r = await assessBusinessFraud("sys", [], log);
    expect(seen.url).toBe(
      "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    );
    expect(seen.auth).toBe("Bearer gem-key");
    expect(r.ok).toBe(true);
  });
});

describe("screenshot validation", () => {
  const png =
    "data:image/png;base64," +
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]).toString("base64");
  test("accepts a real PNG", () => {
    expect(validateImage(png)).toEqual({ ok: true, mime: "image/png" });
  });
  test("rejects a mislabelled file", () => {
    const fake = "data:image/png;base64," + Buffer.from("not an image at all").toString("base64");
    expect(validateImage(fake)).toEqual({ ok: false, code: "image_signature" });
  });
  test("rejects a JPEG declared as PNG", () => {
    const jpeg =
      "data:image/png;base64," +
      Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0]).toString("base64");
    expect(validateImage(jpeg)).toEqual({ ok: false, code: "image_mismatch" });
  });
  test("rejects non-image mime and oversize payloads", () => {
    expect(validateImage("data:application/pdf;base64,AAAA").ok).toBe(false);
    const big = "data:image/png;base64," + "A".repeat(9 * 1024 * 1024 * 2);
    expect(validateImage(big)).toEqual({ ok: false, code: "image_too_large" });
  });
});

describe("privacy-safe logging", () => {
  test("logger emits only provider, status and correlation id", () => {
    const lines: string[] = [];
    const orig = console.error;
    console.error = (m: any) => lines.push(String(m));
    makeLogger("cid1234")("web_risk", 503);
    console.error = orig;
    expect(lines).toEqual(["app=privacore provider=web_risk status=503 cid=cid1234"]);
  });
});
