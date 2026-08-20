/**
 * Structured AI analysis. The provider key is read at request time and never
 * leaves the server; no prompt or model output is ever logged.
 *
 * Default provider is Google Gemini through its OpenAI-compatible endpoint,
 * so PC_AI_BASE_URL can be repointed at any OpenAI-compatible gateway.
 */
import { env, fetchWithTimeout, isAbort, type LogProvider } from "./runtime.server";
import { RISK_LEVELS } from "./types";

const DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai";
const DEFAULT_MODEL = "gemini-2.5-pro";

const TOOL = {
  type: "function",
  function: {
    name: "assess_business_fraud",
    description: "Return a structured business fraud assessment.",
    parameters: {
      type: "object",
      properties: {
        risk_level: {
          type: "string",
          enum: RISK_LEVELS as unknown as string[],
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
          description: "True when someone appears to be posing as a trusted person or organisation.",
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
} as const;

export type AiOutcome =
  | { ok: true; assessment: Record<string, any> }
  | { ok: false; code: string; status: number };

export async function assessBusinessFraud(
  systemPrompt: string,
  userContent: unknown[],
  log: LogProvider,
): Promise<AiOutcome> {
  const apiKey = env("PC_AI_API_KEY");
  if (!apiKey) {
    log("ai_provider", "no_key");
    return { ok: false, code: "ai_unavailable", status: 503 };
  }
  const baseUrl = (env("PC_AI_BASE_URL") || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const model = env("PC_AI_MODEL") || DEFAULT_MODEL;

  let response: Response;
  try {
    response = await fetchWithTimeout(
      `${baseUrl}/chat/completions`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: userContent },
          ],
          tools: [TOOL],
          tool_choice: { type: "function", function: { name: "assess_business_fraud" } },
        }),
      },
      30000,
    );
  } catch (e) {
    log("ai_provider", isAbort(e) ? "timeout" : "exception");
    return { ok: false, code: "ai_unavailable", status: 504 };
  }

  if (!response.ok) {
    log("ai_provider", response.status);
    if (response.status === 429) return { ok: false, code: "ai_rate_limited", status: 429 };
    if (response.status === 402) return { ok: false, code: "ai_credits", status: 402 };
    return { ok: false, code: "ai_error", status: 500 };
  }

  try {
    const data = await response.json();
    const toolCall = data?.choices?.[0]?.message?.tool_calls?.[0];
    if (!toolCall) {
      log("ai_provider", "no_tool_call");
      return { ok: false, code: "ai_error", status: 500 };
    }
    return { ok: true, assessment: JSON.parse(toolCall.function.arguments) };
  } catch {
    log("ai_provider", "parse_error");
    return { ok: false, code: "ai_error", status: 500 };
  }
}