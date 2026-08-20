import { useRef, useState } from "react";

import {
  CATEGORIES,
  MAX_IMAGE_BYTES,
  MAX_TEXT_CHARS,
  TURNSTILE_SITE_KEY,
  runCheck,
  type Assessment,
  type RiskLevel,
} from "@/lib/business-check";
import { Turnstile, resetTurnstile } from "@/components/Turnstile";

const RISK_STYLES: Record<RiskLevel, { chip: string; bar: string; note: string }> = {
  "HIGH RISK": {
    chip: "bg-risk-high text-risk-high-foreground",
    bar: "bg-risk-high",
    note: "Strong evidence of fraud. Do not act on this request.",
  },
  SUSPICIOUS: {
    chip: "bg-risk-suspicious text-risk-suspicious-foreground",
    bar: "bg-risk-suspicious",
    note: "Real warning signs found. Verify before doing anything.",
  },
  "NO KNOWN THREAT DETECTED": {
    chip: "bg-risk-none text-risk-none-foreground",
    bar: "bg-risk-none",
    note: "No known threat found. This is not proof the request is legitimate.",
  },
  "INSUFFICIENT EVIDENCE": {
    chip: "bg-risk-unknown text-risk-unknown-foreground",
    bar: "bg-risk-unknown",
    note: "Not enough information to reach a finding.",
  },
};

const STEPS = [
  { key: "stop", label: "STOP", hint: "Do not do this yet" },
  { key: "verify", label: "VERIFY", hint: "Confirm independently" },
  { key: "call", label: "CALL", hint: "Use contact details you already hold" },
] as const;

export function BusinessFraudCheck() {
  const [category, setCategory] = useState<string>("payment_invoice");
  const [message, setMessage] = useState("");
  const [image, setImage] = useState<string | null>(null);
  const [imageName, setImageName] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const resultRef = useRef<HTMLDivElement | null>(null);

  const canSubmit = !loading && (message.trim().length >= 2 || image !== null);

  function onPickFile(file: File | undefined) {
    setNotice(null);
    if (!file) return;
    if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
      setNotice("Use a PNG, JPEG or WebP screenshot.");
      return;
    }
    if (file.size > MAX_IMAGE_BYTES) {
      setNotice("That image is too large. Use an image under 8 MB.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setImage(typeof reader.result === "string" ? reader.result : null);
      setImageName(file.name);
    };
    reader.onerror = () => setNotice("That screenshot couldn't be read. Try again.");
    reader.readAsDataURL(file);
  }

  function clearImage() {
    setImage(null);
    setImageName("");
    if (fileRef.current) fileRef.current.value = "";
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setNotice(null);
    setAssessment(null);

    if (!token) {
      setNotice("Please complete the human check just below the button, then try again.");
      return;
    }

    setLoading(true);
    const outcome = await runCheck({
      message: message.trim(),
      image,
      category,
      turnstileToken: token,
    });
    setLoading(false);
    setToken(null);
    resetTurnstile();

    if (outcome.kind === "result") {
      setAssessment(outcome.assessment);
      requestAnimationFrame(() =>
        resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }),
      );
    } else {
      setNotice(outcome.message);
    }
  }

  return (
    <div className="mx-auto w-full max-w-3xl px-4 pb-24">
      <form
        onSubmit={onSubmit}
        className="rounded-2xl border border-border bg-card p-5 shadow-panel sm:p-7"
      >
        <fieldset className="mb-6">
          <legend className="mb-3 text-sm font-semibold text-foreground">
            What are you checking?
          </legend>
          <div className="flex flex-wrap gap-2">
            {CATEGORIES.map((c) => {
              const active = c.value === category;
              return (
                <button
                  type="button"
                  key={c.value}
                  onClick={() => setCategory(c.value)}
                  aria-pressed={active}
                  className={`rounded-full border px-3.5 py-2 text-sm transition-colors ${
                    active
                      ? "border-ink bg-ink text-ink-foreground"
                      : "border-border bg-background text-muted-foreground hover:border-brand hover:text-foreground"
                  }`}
                >
                  {c.label}
                </button>
              );
            })}
          </div>
        </fieldset>

        <label htmlFor="content" className="mb-2 block text-sm font-semibold text-foreground">
          Paste the email, invoice wording, link or request
        </label>
        <textarea
          id="content"
          value={message}
          onChange={(e) => setMessage(e.target.value.slice(0, MAX_TEXT_CHARS))}
          rows={8}
          placeholder={
            "Paste the full message, including the sender address, any link, the amount, and any new banking details."
          }
          className="w-full resize-y rounded-xl border border-input bg-background p-3.5 text-sm text-foreground outline-none focus:border-brand focus:ring-2 focus:ring-ring/40"
        />
        <div className="mt-1.5 flex items-center justify-between text-xs text-muted-foreground">
          <span>Never include passwords, MFA codes or full account numbers.</span>
          <span>
            {message.length}/{MAX_TEXT_CHARS}
          </span>
        </div>

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <input
            ref={fileRef}
            id="screenshot"
            type="file"
            accept="image/png,image/jpeg,image/webp"
            className="sr-only"
            onChange={(e) => onPickFile(e.target.files?.[0])}
          />
          <label
            htmlFor="screenshot"
            className="cursor-pointer rounded-lg border border-input bg-background px-3.5 py-2 text-sm font-medium text-foreground hover:border-brand"
          >
            Attach a screenshot
          </label>
          {imageName ? (
            <span className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className="max-w-[16rem] truncate">{imageName}</span>
              <button
                type="button"
                onClick={clearImage}
                className="underline underline-offset-2 hover:text-foreground"
              >
                Remove
              </button>
            </span>
          ) : (
            <span className="text-sm text-muted-foreground">PNG, JPEG or WebP, up to 8 MB.</span>
          )}
        </div>

        <button
          type="submit"
          disabled={!canSubmit}
          className="mt-6 w-full rounded-xl bg-ink px-5 py-3.5 text-base font-semibold text-ink-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
        >
          {loading ? "Checking…" : "Check this request"}
        </button>

        <div className="mt-4">
          {TURNSTILE_SITE_KEY ? (
            <Turnstile
              siteKey={TURNSTILE_SITE_KEY}
              action="check-business-fraud"
              onToken={setToken}
            />
          ) : (
            <p className="text-center text-xs text-muted-foreground">
              Human verification is not configured for this environment yet.
            </p>
          )}
        </div>

        {notice ? (
          <p
            role="status"
            className="mt-4 rounded-lg border border-border bg-accent px-3.5 py-3 text-sm text-accent-foreground"
          >
            {notice}
          </p>
        ) : null}

        <p className="mt-5 text-center text-xs text-muted-foreground">
          5 free checks per day. Nothing you paste is used to identify you.
        </p>
      </form>

      <div ref={resultRef}>
        {assessment ? <Result assessment={assessment} /> : null}
      </div>
    </div>
  );
}

function Result({ assessment }: { assessment: Assessment }) {
  const style = RISK_STYLES[assessment.risk_level] ?? RISK_STYLES.SUSPICIOUS;
  const threats = {
    ...(assessment.url_check?.confirmed_threats ?? {}),
    ...(assessment.url_check?.virustotal_threats ?? {}),
  };

  return (
    <section
      aria-live="polite"
      className="mt-8 overflow-hidden rounded-2xl border border-border bg-card shadow-panel"
    >
      <div className={`h-1.5 w-full ${style.bar}`} />
      <div className="p-5 sm:p-7">
        <div className="flex flex-wrap items-center gap-3">
          <span
            className={`rounded-full px-3.5 py-1.5 text-sm font-bold tracking-wide ${style.chip}`}
          >
            {assessment.risk_level}
          </span>
          <span className="text-sm text-muted-foreground">
            {assessment.category_label} · Confidence: {assessment.confidence}
          </span>
        </div>

        <h2 className="mt-4 text-2xl font-bold text-foreground">{assessment.fraud_type}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{style.note}</p>
        <p className="mt-4 text-[0.95rem] leading-relaxed text-foreground">
          {assessment.explanation}
        </p>

        {assessment.business_impact ? (
          <p className="mt-4 rounded-lg border border-border bg-accent px-3.5 py-3 text-sm font-medium text-accent-foreground">
            What's at stake: {assessment.business_impact}
          </p>
        ) : null}

        <h3 className="mt-8 text-sm font-semibold tracking-widest text-muted-foreground uppercase">
          Stop · Verify · Call™
        </h3>
        <ol className="mt-3 space-y-3">
          {STEPS.map((step, i) => {
            const lines = (assessment[step.key] ?? []) as string[];
            if (lines.length === 0) return null;
            return (
              <li
                key={step.key}
                className="rounded-xl border border-border bg-background p-4"
              >
                <div className="flex items-baseline gap-3">
                  <span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-ink text-xs font-bold text-ink-foreground">
                    {i + 1}
                  </span>
                  <div>
                    <p className="font-display text-base font-bold tracking-wide text-foreground">
                      {step.label}
                    </p>
                    <p className="text-xs text-muted-foreground">{step.hint}</p>
                  </div>
                </div>
                <ul className="mt-3 space-y-1.5 pl-10">
                  {lines.map((line, idx) => (
                    <li key={idx} className="text-[0.95rem] leading-relaxed text-foreground">
                      {line}
                    </li>
                  ))}
                </ul>
              </li>
            );
          })}
        </ol>

        {assessment.red_flags?.length ? (
          <>
            <h3 className="mt-8 text-sm font-semibold tracking-widest text-muted-foreground uppercase">
              What we noticed
            </h3>
            <ul className="mt-3 space-y-2">
              {assessment.red_flags.map((flag, idx) => (
                <li key={idx} className="flex gap-2.5 text-[0.95rem] text-foreground">
                  <span aria-hidden className="mt-2 size-1.5 shrink-0 rounded-full bg-brand" />
                  <span>{flag}</span>
                </li>
              ))}
            </ul>
          </>
        ) : null}

        {Object.keys(threats).length > 0 ? (
          <div className="mt-8 rounded-xl border border-risk-high/40 bg-risk-high/5 p-4">
            <h3 className="text-sm font-semibold text-foreground">Link reputation</h3>
            <ul className="mt-2 space-y-1.5">
              {Object.entries(threats).map(([url, detail]) => (
                <li key={url} className="text-sm break-all text-foreground">
                  <span className="font-medium">{url}</span> — {detail}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        <p className="mt-8 rounded-xl border border-ink/15 bg-ink/5 p-4 text-sm font-medium text-foreground">
          {assessment.universal_rule}
        </p>

        {assessment.free_checks ? (
          <p className="mt-4 text-center text-xs text-muted-foreground">
            {assessment.free_checks.remaining} of {assessment.free_checks.limit} free checks left
            today.
          </p>
        ) : null}

        <p className="mt-4 text-center text-xs text-muted-foreground">
          This is guidance, not legal, financial or security advice. If money has already been
          sent, contact your bank immediately and report it to the Canadian Anti-Fraud Centre.
        </p>
      </div>
    </section>
  );
}