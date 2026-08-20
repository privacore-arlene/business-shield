/**
 * Shared, client-safe contract for the PrivaCore Business Fraud Check.
 * No secrets, no environment access — imported by both browser and server.
 */

export const RISK_LEVELS = [
  "HIGH RISK",
  "SUSPICIOUS",
  "NO KNOWN THREAT DETECTED",
  "INSUFFICIENT EVIDENCE",
] as const;

export type RiskLevel = (typeof RISK_LEVELS)[number];

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
/** An 8 MB image grows ~33% in base64; leave headroom for the JSON envelope. */
export const MAX_BODY_BYTES = 12 * 1024 * 1024;

export const FREE_DAILY_LIMIT = 5;
export const IP_DAILY_LIMIT = 20;
export const IP_BURST_LIMIT = 8;

export const TURNSTILE_ACTION = "check-business-fraud";

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