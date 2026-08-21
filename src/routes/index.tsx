import { createFileRoute } from "@tanstack/react-router";

import logo from "@/assets/privacore-logo.png.asset.json";
import { BusinessFraudCheck } from "@/components/BusinessFraudCheck";

const TITLE = "PrivaCore Business Fraud Check";
const DESCRIPTION =
  "Check a suspicious invoice, banking change, supplier email or link before your business pays. Free, private, and built for Canadian businesses.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: `${TITLE} — Stop invoice, banking and email fraud` },
      { name: "description", content: DESCRIPTION },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESCRIPTION },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const PRIORITIES = [
  {
    title: "Business email compromise",
    body: "Spoofed or hijacked mailboxes, lookalike sender domains, and payment instructions that change mid-thread.",
  },
  {
    title: "Changed banking details",
    body: "\u201cOur bank has changed\u201d letters, new transit or account numbers, and updated remittance instructions.",
  },
  {
    title: "Invoice and payment diversion",
    body: "Altered or duplicate invoices, unfamiliar payment portals, and pressure to release funds today.",
  },
];

function Index() {
  return (
    <main className="min-h-screen bg-background">
      <header className="bg-ink text-ink-foreground">
        <div className="mx-auto w-full max-w-3xl px-4 py-14 sm:py-20">
          <img
            src={logo.url}
            alt="The PrivaCore Group — fraud prevention and cybersecurity for small business"
            className="h-16 w-auto sm:h-20"
            width={1536}
            height={1024}
          />
          <h1 className="mt-6 text-4xl font-bold sm:text-5xl">Business Fraud Check</h1>
          <p className="mt-4 max-w-xl text-base leading-relaxed text-ink-foreground/80">
            Before your business pays an invoice, updates supplier banking details or acts on an
            urgent request, check it here. Built for Canadian businesses and the people who
            actually process the payment.
          </p>
          <p className="mt-6 inline-block rounded-full border border-brand/50 px-4 py-2 text-sm font-semibold tracking-wide">
            Every result follows STOP · VERIFY · CALL™
          </p>
        </div>
      </header>

      <div className="-mt-8">
        <BusinessFraudCheck />
      </div>

      <section className="border-t border-border bg-accent/40">
        <div className="mx-auto w-full max-w-3xl px-4 py-14">
          <h2 className="text-2xl font-bold text-foreground">What this checks first</h2>
          <div className="mt-6 grid gap-4 sm:grid-cols-3">
            {PRIORITIES.map((p) => (
              <div key={p.title} className="rounded-xl border border-border bg-card p-4">
                <h3 className="text-base font-semibold text-foreground">{p.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{p.body}</p>
              </div>
            ))}
          </div>
          <p className="mt-8 text-sm leading-relaxed text-muted-foreground">
            A clean result never means a request is legitimate or approved. It means no known
            threat was found. Confirm every payment and banking change using contact details you
            already hold — never the phone number, email address or link inside the request.
          </p>
        </div>
      </section>

      <footer className="border-t border-border py-8">
        <p className="mx-auto max-w-3xl px-4 text-center text-xs text-muted-foreground">
          © {new Date().getFullYear()} PrivaCore Group. STOP · VERIFY · CALL™ is a trademark of
          PrivaCore Group. Guidance only — not legal, financial or security advice.
        </p>
      </footer>
    </main>
  );
}
