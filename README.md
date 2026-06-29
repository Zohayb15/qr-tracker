# QR Scan Tracker

A full-stack web app for generating QR codes that automatically track every
scan — location, device, browser, and repeat visits — with real per-user
accounts, a production Postgres database, and a complete password-reset
flow. Built solo, deployed live, and debugged through several real
production issues along the way (see [Challenges & Solutions](#challenges--solutions)
below).

**Live demo:** https://qr-tracker-o43k.onrender.com
*(free-tier hosting — the app may take 30–50 seconds to wake up if it hasn't been visited recently)*

---

## What it does

1. A user signs up for an account and creates a "campaign" — a name plus a
   destination URL (e.g. a flyer landing page, a social link, an event page).
2. The app generates a scannable QR code for that campaign, downloadable as
   PNG or SVG.
3. Every time someone scans that QR code, the app logs data about the
   visit automatically — no input required from the person scanning — and
   redirects them straight to the destination URL.
4. The account owner views a private analytics dashboard: total scans,
   unique visitors, repeat-visit detection, location/device/browser
   breakdowns, a 14-day activity chart, and a full exportable CSV.

## Features

- **Per-user accounts** — sign up, log in, and your campaigns/data are private to your account only
- **Automatic scan analytics** — every scan captures timestamp, approximate location (via IP), device type, OS, browser, and whether it's a repeat visit from the same device, with zero input from the visitor
- **Downloadable QR codes** — PNG and SVG, generated on demand
- **Forgot password** — secure, time-limited (1 hour) email reset links
- **Timezone-aware display** — scan times automatically render in whoever is *viewing* the dashboard's own browser timezone (not a hardcoded zone)
- **CSV export** — raw scan data, ready for further analysis
- **Custom dark UI** — built from scratch with a "scanner viewfinder" visual motif tying the design back to the QR/scanning concept

## Tech stack

- **Backend:** Python, Flask, SQLAlchemy
- **Database:** PostgreSQL (production), SQLite (local development fallback)
- **Frontend:** Server-rendered Jinja templates, vanilla CSS and JavaScript (no frontend framework — deliberately kept lightweight)
- **Auth:** Werkzeug password hashing, `itsdangerous` for signed, time-limited password-reset tokens
- **Email:** Resend (HTTP-based transactional email API)
- **Hosting:** Render (web service) + Neon (Postgres)
- **Libraries:** `qrcode` (QR generation), `user-agents` (device/browser parsing), `requests` (IP geolocation + email API calls)

## Architecture / how it works

- Each QR code encodes a tracking URL (`/q/<code>`), not the destination
  URL directly. When scanned, the server logs the visit, then redirects
  the visitor to the real destination — invisible to the end user.
- **Location** comes from a free IP-geolocation API (ip-api.com), looked up
  server-side from the visitor's IP address.
- **Repeat-visit detection** uses an anonymous, randomly generated cookie
  (no personal data) set on first visit and checked on subsequent ones.
- **Password reset tokens** are stateless and signed (`itsdangerous`),
  encoding the user ID and an expiry, rather than storing reset tokens in
  the database — simpler, with an accepted tradeoff that tokens remain
  valid (not single-use) until they expire.
- **Timezone display** is handled client-side: the server sends raw UTC
  timestamps, and JavaScript in the browser converts them to whatever
  timezone the viewer's own machine is in.

## Challenges & solutions

Real issues hit during development and deployment — and how each was diagnosed:

| Issue | Root cause | Fix |
|---|---|---|
| Accounts kept disappearing after every redeploy | Render's free web services have an *ephemeral filesystem* — SQLite database files get wiped on every redeploy/restart | Migrated to a real hosted Postgres database (Neon), which persists independently of app deploys |
| Random `SSL connection has been closed unexpectedly` errors | Serverless Postgres (Neon) aggressively closes idle connections; SQLAlchemy was reusing dead connections from its pool | Enabled `pool_pre_ping` so connections are tested and silently refreshed before use |
| App crashed on deploy with a `psycopg2` import error | Render defaulted to a newer Python version than `psycopg2-binary` had prebuilt wheels for | Pinned the Python version via a `.python-version` file |
| Password reset emails never arrived — no errors anywhere in the logs | Two stacked bugs: (1) Flask's logger had no output handler configured under gunicorn, so `logger.warning`/`.error()` calls were silently swallowed; (2) once logging was fixed, found that Render's free tier **blocks all outbound SMTP traffic** (ports 25/465/587) as an anti-spam measure — Gmail SMTP could never have worked there | Fixed the logging configuration explicitly, then switched email sending from SMTP to **Resend**, an HTTP-based email API unaffected by the SMTP port block |
| Dashboard always showed scan times in UTC | No timezone handling at all initially | Added client-side timezone conversion via JavaScript's `Intl`/`Date` APIs, so each viewer sees their own local time automatically |

## What gets captured on every scan (and what doesn't)

Captured automatically, no input required:
- Timestamp
- Approximate location (city/region, from IP address)
- Device type (mobile / tablet / desktop), OS, and browser
- First-time vs. repeat visitor (anonymous cookie, no personal data)
- Referrer, if any

**Never captured automatically:** phone numbers, names, or emails. This
is a hard technical limitation of the web — no website can read a
visitor's personal contact info just from them loading a page. That data
can only ever come from a form the visitor fills in themselves.

## Running it locally

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(16))")

python3 app.py
```

Open http://127.0.0.1:5000 — you'll be prompted to sign up, then land on
the create-a-QR page. Locally, scans will show "Local/dev" for location
(IP geolocation only works for real public IPs), and password resets log
to the console instead of sending real email unless `RESEND_API_KEY` is set.

## Deploying it yourself

1. Push this repo to GitHub, connect it on Render as a **Web Service**
2. Build command: `pip install -r requirements.txt`
3. Start command: `gunicorn app:app`
4. Add environment variables:
   - `SECRET_KEY` — any random 20+ character string
   - `DATABASE_URL` — a Postgres connection string (Render Postgres or Neon both work)
   - `RESEND_API_KEY` — for password reset emails to actually send (see below)
5. Deploy — Render gives you a public URL

### Email setup (Resend)

Render's free tier blocks outbound SMTP, so this app uses
[Resend](https://resend.com) instead, which sends over HTTPS:

1. Sign up free at resend.com
2. **API Keys** → **Create API Key**
3. Copy the key, set it as `RESEND_API_KEY` in your environment variables

By default, emails send from Resend's shared `onboarding@resend.dev`
address (works immediately, no domain setup). To send from your own
domain, verify it in Resend's dashboard and set `RESEND_FROM_EMAIL`.

## Known limitations

- Password reset tokens are valid for 1 hour and technically reusable
  within that window (not invalidated after first use) — a reasonable
  tradeoff for a small personal project; the fix for tighter security
  would be tracking used tokens in the database
- Free-tier hosting means the app sleeps after 15 minutes of inactivity
  (30–50 second wake-up) and the database has its own free-tier limits

## Project structure

```
app.py                  Flask app: routes, models, auth, scan-logging logic
static/
  favicon.svg            Custom tab icon
templates/
  base.html              Shared layout/styling (dark theme, fonts)
  register.html          Sign-up page
  login.html             Log-in page
  forgot_password.html   Password reset request page
  reset_password.html    Password reset confirmation page
  index.html             Create a campaign / list your own ones
  dashboard.html         Overview of your campaigns
  detail.html            Per-campaign stats, chart, raw log, downloads
requirements.txt
.python-version          Pins Python version for deployment compatibility
```
