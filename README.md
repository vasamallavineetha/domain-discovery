# 🌐 New Domain Discovery Tool

Automatically discovers **500+ newly registered domains** every day from free public sources, exports them to CSV/JSON, and **emails you the report** — even while your laptop is closed.

## How It Works

| # | Source | Method | What it provides |
|---|--------|--------|-----------------|
| 1 | **WhoisDS** | Daily ZIP download | Bulk NRD (Newly Registered Domains) lists |
| 2 | **Certificate Transparency (crt.sh)** | REST API | Domains that just got SSL certificates |
| 3 | **CT Recent Scan** | Pattern matching | Fresh certificates across 20+ TLDs |

## Quick Start (Local)

```bash
# Install dependencies
pip install -r requirements.txt

# Run once (today's domains)
python domain_discovery.py

# Run for a specific date
python domain_discovery.py --date 2026-10-02

# Run and email the results
python domain_discovery.py --email you@gmail.com
```

## 🚀 Auto-Run Daily (GitHub Actions — works even with laptop closed!)

### Step 1: Push this repo to GitHub

```bash
cd /media/vinodrao/Storage-B/Projects/idea_4
git init
git add .
git commit -m "Initial commit: Domain Discovery Tool"
git remote add origin https://github.com/YOUR_USERNAME/domain-discovery.git
git branch -M main
git push -u origin main
```

### Step 2: Create a Gmail App Password

1. Go to [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Sign in with your Gmail account
3. Under "App name", type `Domain Discovery` → click **Create**
4. **Copy the 16-character password** (e.g. `abcd efgh ijkl mnop`)

> ⚠️ You must have **2-Step Verification** enabled on your Google account first.

### Step 3: Add secrets to GitHub

Go to your repo on GitHub → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

Add these 3 secrets:

| Secret Name | Value |
|-------------|-------|
| `GMAIL_ADDRESS` | Your Gmail address (e.g. `you@gmail.com`) |
| `GMAIL_APP_PASS` | The 16-char app password from Step 2 |
| `EMAIL_RECIPIENT` | Where to send reports (can be same as GMAIL_ADDRESS) |

### Step 4: Done! ✅

The workflow runs **automatically every day at 11:30 AM IST (06:00 UTC)**.

You can also trigger it manually:
- Go to your repo → **Actions** tab → **Daily Domain Discovery** → **Run workflow**

## 📧 Email Usage

```bash
# Email to the default address (GMAIL_ADDRESS env var)
python domain_discovery.py --email

# Email to a specific address
python domain_discovery.py --email someone@example.com

# Disable email even if env vars are set
python domain_discovery.py --no-email
```

**Environment variables for email:**

```bash
export GMAIL_ADDRESS="you@gmail.com"
export GMAIL_APP_PASS="abcd efgh ijkl mnop"
export EMAIL_RECIPIENT="recipient@example.com"  # optional, defaults to GMAIL_ADDRESS
```

## Output

Results are saved in the `output/` directory:
- `output/new_domains_YYYY-MM-DD.csv` — CSV with all domains
- `output/new_domains_YYYY-MM-DD.json` — JSON with metadata + domains

On GitHub Actions, results are also saved as **downloadable artifacts** (retained for 30 days).

## All CLI Options

```
python domain_discovery.py [OPTIONS]

Options:
  --date, -d DATE          Target date (YYYY-MM-DD, default: today)
  --format, -f FORMAT      Export format: csv, json, both (default: both)
  --email, -e [RECIPIENT]  Email results after export
  --no-email               Disable email
  --min-domains N          Minimum domains target (default: 500)
  --schedule, -s           Run as local daily scheduler (02:00)
  --help, -h               Show help
```

## Project Structure

```
idea_4/
├── domain_discovery.py           # Main script
├── requirements.txt              # Python dependencies
├── README.md                     # This file
├── .github/
│   └── workflows/
│       └── daily_discovery.yml   # GitHub Actions (auto-run daily)
├── output/                       # Generated CSV/JSON reports
└── logs/                         # Execution logs
```
