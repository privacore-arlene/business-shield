# Business Shield

I want to build a new application called:



PrivaCore Business Fraud Check



I already have a working scam-checking application whose source code is in this GitHub repository:



"https://github.com/privacore-arlene/Scam-Checker"



Use that existing application as the technical foundation for this new application.



IMPORTANT:



This is a NEW application.



Do not modify, overwrite, deploy over, or change the existing Fraud Doctor Scam Checker.



The existing application is designed for seniors and consumers. The new application will be designed for Canadian businesses, initially focusing on builders, contractors and renovators.



FIRST STEP — INSPECT BEFORE BUILDING



Before changing or generating code, inspect the existing GitHub repository and identify:



- application framework and structure;

- frontend components;

- Supabase integration;

- Supabase Edge Functions;

- URL extraction;

- Google Safe Browsing implementation;

- VirusTotal implementation;

- screenshot/image analysis;

- AI analysis architecture;

- Cloudflare Turnstile;

- rate limiting;

- environment-variable handling;

- security controls;

- reusable components.



Reuse proven technical components where appropriate.



Do NOT blindly duplicate consumer-specific code.



CREATE A NEW APPLICATION



Create a separate application based on the reusable architecture.



Working product name:



PrivaCore Business Fraud Check



Positioning:



Check a suspicious payment, invoice, email, supplier request or website before you act.



The new application should use:



STOP · VERIFY · CALL™



as its core fraud-prevention action framework.



KEEP SEPARATE



Do not carry over consumer-specific Fraud Doctor content such as:



- senior-focused language;

- grandparent-scam-specific UI;

- medical/doctor terminology;

- consumer CTAs;

- Fraud Doctor marketing content;

- consumer scam-alert sections unless deliberately required.



The business fraud analysis will eventually focus on:



- business email compromise;

- supplier impersonation;

- changed banking information;

- invoice fraud;

- payment diversion;

- executive impersonation;

- credential phishing;

- fraudulent websites;

- customer payment diversion;

- government/grant impersonation.



Do not build all advanced functionality yet.



GITHUB



The new application must have its own GitHub repository.



Use:



"privacore-arlene/PrivaCore-Business-Fraud-Check"



GitHub will be the source of truth for the code.



Do NOT write the new application into:



"privacore-arlene/Scam-Checker"



HOSTING ARCHITECTURE



Prepare the application for:



Lovable → GitHub → Netlify



Netlify will host the frontend.



Supabase will continue to provide the secure backend/Edge Functions.



Sensitive API credentials must remain server-side.



Do not put VirusTotal, Google threat-intelligence, AI provider, Turnstile secret or Supabase service-role credentials into frontend code.



IMPORTANT



Do not begin making major design decisions or adding advanced functionality until you have inspected the existing repository.



First tell me:



1. What architecture you found.

2. What components can safely be reused.

3. What should NOT be copied.

4. How you recommend separating the new PrivaCore application from Fraud Doctor.

5. Whether anything needs to change before creating the new application.



Then wait for my approval before proceeding with the build.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/8ca023a0-2535-4e3d-a541-704252471543).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
