# Exazon Survey Engine — Master Reference Document
*(Node.js/Next.js panel-tool — personal-use, Exazon-branded, deployed to production)*

---

## 1. Overview

A ground-up Node.js/Next.js + Supabase rebuild of the ExaVerify (PHP) panel-tool logic, for Azii's personal use. Not a replacement for ExaVerify — a separate, parallel tool. Built by porting proven fraud-detection/status-lock/token logic from ExaVerify, then extended with features ExaVerify itself lacked (Billing Dashboard, Analytics, Client Portal, Client-Level Redirect, Multi-Country Link, Audit Log, and more).

**Live Production URL:** `https://exaverifyapisurvey.exazonresearch.com`
**Hosting:** Hostinger Business Plan, hPanel "Deploy Web App" (Node.js) feature — deployment-managed (versioned zip-uploads via "Redeploy", not raw file-editing)
**Database:** Supabase project "Exazon Operation Engine" (`nxfjyyqsccqftocjlmls`) — PostgreSQL
**Stack:** Next.js 16.3.0 (Turbopack, App Router), React 19, Supabase Auth + PostgreSQL

---

## 2. Local Development Setup

- Project path (local): `MyWorldResearch--master\MyWorldResearch--master\`
- `.env.local` required vars: `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`. Optional: `ENCRYPTION_KEY` (has a working hardcoded fallback if omitted — see Security section), `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` (both optional, features silently no-op if absent).
- Run: `npm install` → `npm run dev` → `localhost:3000`
- Admin login uses Supabase Auth directly (real email, e.g. `admin@exazonresearch.com` + password) — no separate "username" system needed if a full email is typed at login.

---

## 3. Deployment (Hostinger)

- Deployed via hPanel → Websites → Web Apps → "Deploy Web App" → "Upload your files" (zip upload, not Git).
- Requires a `server.js` bridge file at project root (Next.js doesn't run via `npm start` directly in Hostinger's Node.js App model):
  ```javascript
  const { createServer } = require('http');
  const { parse } = require('url');
  const next = require('next');
  const dev = false;
  const app = next({ dev });
  const handle = app.getRequestHandler();
  const port = process.env.PORT || 3000;
  app.prepare().then(() => {
    createServer((req, res) => {
      const parsedUrl = parse(req.url, true);
      handle(req, res, parsedUrl);
    }).listen(port, () => console.log(`> Ready on port ${port}`));
  });
  ```
- Zip must exclude `node_modules/` and `.next/` (built server-side via the panel's "npm install" + "npm run build" steps).
- Environment Variables set via hPanel UI (persists across redeployments automatically).
- **To push code updates:** Dashboard → Deployments → "Redeploy" → upload a fresh zip → environment variables need re-confirming (usually pre-filled) → deploy. Hostinger's deployment model is versioned (each deploy = new immutable folder under `hbuilds/versions/...`); direct file-editing via File Manager is NOT the intended workflow and gets overwritten on next deploy.
- SSL, CDN, malware-protection: automatic (Hostinger-managed).

---

## 4. Database Schema (Supabase — `public` schema)

Core tables (from original bootstrap): `clients`, `suppliers`, `projects`, `project_supplier_mappings`, `tracking_logs`, `prescreen_questions`, `project_activities`, `profiles`.

Added throughout development (20 migrations total, all independent — no run-order dependency):
`blocked_ips`, `question_library`, `prescreen_templates`, `prescreen_responses`, `reconcile_records`, `portal_clients`, `project_country_links`, `audit_log`, `dashboard_notes`, plus column-additions to existing tables (`encrypt_uid`, `invoice_status`/`invoice_no`/`invoice_notes` on projects, `client_code` on clients, `country`/`city`/`device`/`browser` on tracking_logs, role-migration on profiles).

---

## 5. Full Feature List

### Core Respondent-Flow
- Entry (`/r/[unique_code]`) → optional Prescreener (`/prescreen/[unique_code]`) → Client Survey → Completion/Termination (`/panel/redirect/[status]`)
- **Status-Lock**: first-write-wins; repeat hits never overwrite a locked result
- **Fraud-Detection**: Speeder (LOI-based), Duplicate-UID, Same-IP — quality-score formula: `100 − 40(speeder) − 30(duplicate) − 20(same-ip)`, matches ExaVerify's real (non-"AI") logic exactly
- **Global Vendor-Pause**: supplier `status='Inactive'` blocks traffic across all projects instantly
- **Blocked-IP enforcement**: real-time check at both entry routes
- **Universal Token System**: 41 identifier aliases (uid/pid/respondentid/clickid/sid/studyid/projectcode/etc.) × 7 bracket-styles (`{{}}`, `[]`, `[#...#]`, `{}`, `%%`, `<>`, `$$`) + situational tokens (loi, ip, vid, date, timestamp)
- **Postback-Status Tracking**: "Redirect" (default) or "Show Page" mode per-supplier; background vendor-postback with status tracking (pending/sent/failed/not_applicable)
- **Per-Project Encrypt-UID Toggle**: default ON; project owner can disable if client's survey platform needs the raw original ID
- **Prescreener answers are saved** to `prescreen_responses` (real capture, not discarded)
- **Geo/Device/Browser Tracking**: real IP-geolocation (ip-api.com + ipapi.co fallback, free, no API key) + User-Agent parsing — feeds IP Tracker and Analytics
- **Telegram Real-Time Alerts**: Speeder-detected and Quota-reached events (opt-in via env vars, silent no-op if not configured)
- **Multi-Country Link**: per-project country-specific override survey-URLs, auto-selected via geo-detected respondent country (reuses existing `link_type='Country'` field)
- **Client-Level Redirect**: permanent per-client URL (`?client=CLTxxxx&uid=...`) that resolves the correct project across ALL of a client's projects — generated via "Get Permanent Redirect Link" button on Clients list

### Reports (all real data, CSV export on every one)
Client Report, Supplier Report, PM Activity Report, Group Report (Client/Country/Category), TSign (Trend & Signal) Report (daily fraud-signal trend with anomaly-flagging).

### Management Tools
- Client/Supplier/Project CRUD (Single/Child-cloning/ReContact creation)
- Project ⇄ Supplier Mapping (Survey-Link generation, per-mapping CPI/Quota/Prescreener-toggle/Traffic-toggle)
- Question Library (real CRUD) + Prescreen Template Library (reusable, built from Question Library)
- IP Tracker (real search + block/unblock, now shows real Geo/Device/Browser) + Blocked-IPs list
- Redirect Status / Search & Lookup (rich filtering, CSV download)
- Encryption Lookup Tool (UID ↔ Encrypted conversion)
- **Vendor Detail Page** (`/suppliers/[id]`): aggregate stats, assigned projects, recent-100-leads with search, pause/activate
- **Respondent Detail Page** (`/respondent?uid=...&pid=...`): session details, quality-score breakdown with reasons, real prescreen answers

### Billing & Finance
- **Billing Dashboard**: Revenue (completes × CPI) / Cost (completes × supplier_cpi) / Margin per-project, summary cards, inline invoice-status (paid/unpaid) editing
- **Billing-Dispute Reconciliation**: manual entry (we-sent/our-completes/client-accepted/client-rejected → auto difference/dispute-amount) + CSV-upload comparison against real tracking_logs (Matched/Mismatched/Missing)
- **Feasibility Calculator**: standalone, no DB — sample/IR/LOI/timeline inputs, difficulty-tag multipliers (Low IR, Medical, B2B, Long/Short LOI, Urgent, Webcam, Multi-country, Rural, Sensitive), Revenue/Cost/Margin output, matches ExaVerify's original formula

### Analytics & Oversight
- **Analytics Dashboard**: custom lightweight SVG charts (no chart-library dependency) — Daily Trend line-chart, Status/Device/Country breakdown bar-lists, date-range filter
- **Audit Log**: automatic logging of IP block/unblock and client/supplier/project deletion (via `logAudit()` helper, easily extendable to more actions)
- **Notes**: simple sticky-notes widget

### Client-Facing
- **Client Portal** (`/client-portal/login` + `/client-portal/dashboard`): secure per-client login (username + salted-hashed password via Node's built-in `crypto.scrypt`, no external bcrypt dependency), session via httpOnly cookie, re-validated against DB on every load (instant lockout on deactivation). Shows only that client's projects — real Completed/Target/Progress, CSV export. **Never exposes** pricing, vendor identity, or fraud-detection data.
- Admin-side management at `/client-accounts` — create accounts, auto-scoped to a client's projects (or extra manually-specified project IDs)

### Security & Access Control
- **3-Tier Role System**: `superadmin` (full control, only role that can access `/admin` Team-management and `/admin-login`) / `manager` (normal day-to-day access, default for new users) / `viewer` (read-only tier; a `checkWriteAccess()` helper exists but is not yet wired into every write-action — matches ExaVerify's own "reserved for future" scope)
- **Change Password**: self-service, via Supabase Auth `updateUser()` called through a server action (must NOT be called directly from a client component — see Known Pitfalls)

---

## 6. Branding

Fully Exazon Research branded (logo extracted from ExaVerify's own `pages/complete.html`, dark-navy/blue/gold color scheme, full nav + 3-column footer matching `exazonresearch.com`). All "MyWorldResearch"/"MWR" references removed from the entire codebase, including the respondent-facing prescreener and survey-paused pages. The internal login-email domain suffix (`@exazonresearch.com`, used only as a fallback when a bare username without `@` is typed) was also updated — confirmed safe since real logins use full emails.

---

## 7. Known Pitfalls / Lessons Learned (for future sessions)

1. **Never import `utils/supabase.js` directly into a `"use client"` component.** That file instantiates `supabaseAdmin` (using `SUPABASE_SERVICE_ROLE_KEY`) at module scope unconditionally — importing it client-side crashes with "supabaseKey is required" because the service key isn't in the browser bundle. Always go through a server action instead (see `updatePassword` in `app/login/actions.js` for the fixed pattern).
2. **Hostinger's Node.js App is a versioned-deployment system, not a live file-tree.** Don't hand-edit files via File Manager — always "Redeploy" with a fresh zip.
3. **Migration files can be run in any order** — none of the 20 have cross-dependencies on each other, only on the original bootstrap tables.
4. **`encryptUID`/`decryptUID` has a working hardcoded fallback key** (`'mwr-exazon-secret-key-2026-prod!'`) if `ENCRYPTION_KEY` isn't set — this is fine to rely on, not a blocker.
5. Google/Chrome sometimes autofills the Supabase-login form from saved passwords on first visit to a new production domain — don't assume a person is "not logged in" just because no explicit login step was seen.

---

## 8. Deliberately Deferred (Not Built — By Choice)

- **API Survey Integration** (Lucid/Cint/Dynata real 3rd-party marketplaces): requires a business/partner-approval relationship, not just code — Azii's decision when ready.
- **Token-based public client API / shared-password client dashboard**: security-risk pattern (new unauthenticated attack-surface), no current demand. The safe alternative — the Client Portal with real per-account login — was built instead.
- **Automated Cron Client-Reports**: needs Hostinger's cron-job feature specifically, best set up post-deployment (now that deployment is live, this can be revisited).
- **MWR "Multi Link" concept**: exact intended meaning was never clarified with the friend who built MWR; left on hold.

---

*This document reflects the state of the tool as of its first production deployment (August 2026). Update it whenever a new feature, fix, or architectural decision is made — same practice as the ExaVerify Master Reference Document.*
