/**
 * URL reputation. LOOKUP ONLY — no URL is ever submitted for scanning and no
 * user content leaves this module apart from the extracted URLs themselves.
 */
import { env, fetchWithTimeout, isAbort, type LogProvider } from "./runtime.server";

export type SourceStatus = "ok" | "threat" | "timeout" | "error" | "no_key";
export type CheckResult = { status: SourceStatus; threats: Record<string, string> };

export function extractUrls(text: string): string[] {
  const urlRegex = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi;
  const matches = text.match(urlRegex) || [];
  const cleaned = matches.map((u) => {
    let url = u.replace(/[.,;:!?)\]}'"]+$/, "");
    if (url.startsWith("www.")) url = "http://" + url;
    return url;
  });
  return Array.from(new Set(cleaned)).slice(0, 5);
}

/** VirusTotal v3 — cached lookup only. URLs are never submitted. */
export async function checkVirusTotal(
  urls: string[],
  log: LogProvider,
): Promise<CheckResult> {
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
        const id = Buffer.from(url, "utf8")
          .toString("base64")
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
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
          log("virustotal", cached.status);
        }
      } catch (e) {
        hadFailure = true;
        if (isAbort(e)) hadTimeout = true;
        log("virustotal", isAbort(e) ? "timeout" : "exception");
      }
    }),
  );

  if (Object.keys(threats).length > 0) return { status: "threat", threats };
  if (hadFailure) return { status: hadTimeout ? "timeout" : "error", threats };
  return { status: "ok", threats };
}

/** Google Safe Browsing v4 — 5s hard timeout. */
export async function checkSafeBrowsing(
  urls: string[],
  log: LogProvider,
): Promise<CheckResult> {
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
      log("safe_browsing", res.status);
      return { status: "error", threats: {} };
    }
    const data = await res.json();
    const threats: Record<string, string> = {};
    for (const m of data.matches || []) threats[m.threat.url] = m.threatType;
    return { status: Object.keys(threats).length > 0 ? "threat" : "ok", threats };
  } catch (e) {
    log("safe_browsing", isAbort(e) ? "timeout" : "exception");
    return { status: isAbort(e) ? "timeout" : "error", threats: {} };
  }
}