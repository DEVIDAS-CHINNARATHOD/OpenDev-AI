"""
secret_scanner.py — Exposed secret and credential detector.

Skips .env.example, .env.sample, .env.template (safe files).
Detects 20+ credential types: AWS/GCP/Azure, GitHub, Stripe, Firebase,
MongoDB, Supabase, PostgreSQL, OpenAI, Anthropic, Discord, private keys,
JWT, passwords, and more.

Each secret type includes a fix_prompt_template so the LLM can generate
a precise, deep-research fix tailored to that secret's exposure context.
"""
from __future__ import annotations

import fnmatch
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secret pattern definitions (with LLM fix prompt templates)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, dict[str, Any]] = {
    "aws_access_key": {
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "high",
        "description": "AWS Access Key ID",
        "fix_prompt_template": (
            "SECURITY INCIDENT: An AWS Access Key ID (`AKIA...`) was found hardcoded in "
            "`{file}` line {line}. Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Immediately rotate the exposed key in the AWS IAM console and revoke the old one.\n"
            "2. Remove the hardcoded key from the source file and all git history "
            "(use `git filter-branch` or BFG Repo Cleaner).\n"
            "3. Store credentials using AWS IAM roles (for EC2/Lambda) or environment variables "
            "loaded via AWS Secrets Manager / SSM Parameter Store.\n"
            "4. Add `*.env`, `*.pem`, and credentials files to `.gitignore`.\n"
            "5. Enable AWS CloudTrail to audit any usage of the exposed key.\n\n"
            "Rewrite `{file}` to use `boto3.session.Session()` with no hardcoded credentials. "
            "Return the complete corrected file."
        ),
    },
    "github_token": {
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        "severity": "high",
        "description": "GitHub personal access token",
        "fix_prompt_template": (
            "SECURITY INCIDENT: A GitHub PAT was found hardcoded in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Immediately revoke the token at https://github.com/settings/tokens.\n"
            "2. Remove it from all source files and git history.\n"
            "3. Replace with an environment variable: `os.environ['GITHUB_TOKEN']` or "
            "`process.env.GITHUB_TOKEN`.\n"
            "4. Use GitHub Actions secrets for CI/CD pipelines (`${{ secrets.GITHUB_TOKEN }}`).\n"
            "5. Prefer fine-grained PATs with minimal scopes.\n\n"
            "Rewrite `{file}` to read the token from the environment. "
            "Return the complete corrected file."
        ),
    },
    "slack_token": {
        "pattern": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
        "severity": "high",
        "description": "Slack API token",
        "fix_prompt_template": (
            "SECURITY INCIDENT: A Slack API token was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Revoke the token at https://api.slack.com/apps and regenerate.\n"
            "2. Remove from source — store as `SLACK_TOKEN` environment variable.\n"
            "3. For bots, use Slack's OAuth flow; store tokens in a secrets manager.\n"
            "4. Audit Slack audit logs for any unauthorized API usage.\n\n"
            "Rewrite `{file}` to read `SLACK_TOKEN` from environment. "
            "Return the complete corrected file."
        ),
    },
    "slack_webhook": {
        "pattern": re.compile(
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"
        ),
        "severity": "high",
        "description": "Slack Webhook URL",
        "fix_prompt_template": (
            "SECURITY INCIDENT: A Slack Webhook URL was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Regenerate the webhook at https://api.slack.com/apps — old URL becomes invalid.\n"
            "2. Store the new URL in `SLACK_WEBHOOK_URL` environment variable.\n"
            "3. Anyone with a webhook URL can post to your channel — treat it as a secret.\n\n"
            "Rewrite `{file}` to use `os.environ['SLACK_WEBHOOK_URL']`. "
            "Return the complete corrected file."
        ),
    },
    "stripe_live_key": {
        "pattern": re.compile(r"(?:sk|pk)_live_[0-9a-zA-Z]{24,}"),
        "severity": "high",
        "description": "Stripe live API key",
        "fix_prompt_template": (
            "CRITICAL SECURITY INCIDENT: A LIVE Stripe API key was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. IMMEDIATELY roll the key in the Stripe Dashboard > Developers > API keys.\n"
            "2. Review Stripe logs for unauthorised charges or data access.\n"
            "3. Remove from code and git history immediately.\n"
            "4. Store as `STRIPE_SECRET_KEY` environment variable — NEVER commit live keys.\n"
            "5. Use Stripe's restricted keys with minimum required permissions.\n\n"
            "Rewrite `{file}` to use `os.environ['STRIPE_SECRET_KEY']`. "
            "Return the complete corrected file."
        ),
    },
    "stripe_test_key": {
        "pattern": re.compile(r"(?:sk|pk)_test_[0-9a-zA-Z]{24,}"),
        "severity": "medium",
        "description": "Stripe test API key",
        "fix_prompt_template": (
            "A Stripe TEST key was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "FIX REQUIRED:\n"
            "1. Test keys are lower risk but should still not be committed.\n"
            "2. Move to `STRIPE_TEST_KEY` environment variable.\n"
            "3. Establish a habit of never committing any Stripe key (live or test).\n\n"
            "Rewrite `{file}` to use `os.environ['STRIPE_TEST_KEY']`. "
            "Return the complete corrected file."
        ),
    },
    "google_firebase_api_key": {
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "high",
        "description": "Google / Firebase API key",
        "fix_prompt_template": (
            "SECURITY INCIDENT: A Google/Firebase API key was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Restrict the key in Google Cloud Console > APIs & Services > Credentials "
            "(restrict to specific APIs and HTTP referrers/IPs).\n"
            "2. For server-side use, move to `GOOGLE_API_KEY` environment variable.\n"
            "3. For Firebase client-side SDKs, keys are expected to be public BUT must be "
            "restricted with Firebase Security Rules and App Check.\n"
            "4. Enable API key restrictions to prevent abuse.\n\n"
            "Rewrite `{file}` to load the key from environment for server-side usage. "
            "Return the complete corrected file."
        ),
    },
    "firebase_config": {
        "pattern": re.compile(
            r'(?i)(?:firebaseConfig|initializeApp)\s*\(\s*\{[^}]*apiKey\s*:\s*["\'][^"\']{10,}["\']'
        ),
        "severity": "high",
        "description": "Firebase client config with API key",
        "fix_prompt_template": (
            "A Firebase client config with API key was found hardcoded in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Firebase client config keys are designed for public use but MUST be protected "
            "by Firebase Security Rules and Firebase App Check.\n"
            "2. Move config values to environment variables prefixed `NEXT_PUBLIC_` (Next.js) "
            "or `REACT_APP_` (CRA) so they are injected at build time.\n"
            "3. Enable Firebase App Check (reCAPTCHA Enterprise) to prevent API abuse.\n"
            "4. Set strict Firestore/Realtime Database security rules (deny all by default).\n\n"
            "Rewrite `{file}` to load Firebase config from environment variables. "
            "Return the complete corrected file."
        ),
    },
    "firebase_service_account": {
        "pattern": re.compile(r'"type"\s*:\s*"service_account"'),
        "severity": "high",
        "description": "Firebase service account credentials",
        "fix_prompt_template": (
            "CRITICAL: Firebase service account credentials found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Service account keys grant admin-level access — rotate immediately in Firebase console.\n"
            "2. NEVER commit service account JSON files. Add `*serviceAccount*.json` to .gitignore.\n"
            "3. Use Google's Application Default Credentials (ADC) in production: "
            "set `GOOGLE_APPLICATION_CREDENTIALS` env var to the file path on the server, "
            "or use Workload Identity Federation for GCP/cloud environments.\n"
            "4. Remove the file from git history using BFG Repo Cleaner.\n\n"
            "Rewrite `{file}` to use ADC or env-variable-based credential loading. "
            "Return the complete corrected file."
        ),
    },
    "mongodb_uri": {
        "pattern": re.compile(
            r"mongodb(?:\+srv)?://[A-Za-z0-9_\-]+:[^@\s\"'<>]{4,}@[A-Za-z0-9\-\.]+"
        ),
        "severity": "high",
        "description": "MongoDB connection string with credentials",
        "fix_prompt_template": (
            "SECURITY INCIDENT: A MongoDB URI with credentials was found in `{file}` "
            "line {line}. Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Rotate the MongoDB user password immediately in MongoDB Atlas or your MongoDB server.\n"
            "2. Move the entire URI to `MONGODB_URI` environment variable.\n"
            "3. Ensure the MongoDB user has minimal required permissions (principle of least privilege).\n"
            "4. Enable MongoDB Atlas IP Access List to restrict connections to known IPs only.\n"
            "5. Enable MongoDB audit logging to detect any unauthorised access.\n\n"
            "Rewrite `{file}` to use `os.environ['MONGODB_URI']`. "
            "Return the complete corrected file."
        ),
    },
    "supabase_service_key": {
        "pattern": re.compile(
            r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
        ),
        "severity": "high",
        "description": "Supabase / JWT service key",
        "fix_prompt_template": (
            "A Supabase service role key (JWT) was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. The service role key bypasses Row Level Security — this is critical.\n"
            "2. Rotate the key in Supabase Dashboard > Settings > API.\n"
            "3. Store as `SUPABASE_SERVICE_ROLE_KEY` environment variable — only use server-side.\n"
            "4. Use the public anon key for client-side code (with proper RLS policies).\n"
            "5. Enable Supabase RLS on all tables.\n\n"
            "Rewrite `{file}` to load the key from `os.environ['SUPABASE_SERVICE_ROLE_KEY']`. "
            "Return the complete corrected file."
        ),
    },
    "postgres_url": {
        "pattern": re.compile(
            r"postgres(?:ql)?://[A-Za-z0-9_\-]+:[^@\s\"'<>]{4,}@[A-Za-z0-9\-\.]+"
        ),
        "severity": "high",
        "description": "PostgreSQL connection string with credentials",
        "fix_prompt_template": (
            "A PostgreSQL connection string with credentials was found in `{file}` "
            "line {line}. Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Rotate the database user password immediately.\n"
            "2. Move the full URL to `DATABASE_URL` environment variable.\n"
            "3. Restrict the DB user to only the tables/operations it needs (GRANT minimal privileges).\n"
            "4. Ensure `pg_hba.conf` limits connections to trusted IPs only.\n"
            "5. Use connection pooling (PgBouncer) with separate credentials.\n\n"
            "Rewrite `{file}` to use `os.environ['DATABASE_URL']`. "
            "Return the complete corrected file."
        ),
    },
    "sendgrid_key": {
        "pattern": re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
        "severity": "high",
        "description": "SendGrid API key",
        "fix_prompt_template": (
            "A SendGrid API key was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "FIX REQUIRED:\n"
            "1. Revoke the key in SendGrid Dashboard > Settings > API Keys.\n"
            "2. Create a new restricted key with only the required permissions.\n"
            "3. Store as `SENDGRID_API_KEY` environment variable.\n"
            "4. Review SendGrid Activity Feed for any unauthorised email sending.\n\n"
            "Rewrite `{file}` to use `os.environ['SENDGRID_API_KEY']`. "
            "Return the complete corrected file."
        ),
    },
    "twilio_account_sid": {
        "pattern": re.compile(r"\bAC[a-z0-9]{32}\b"),
        "severity": "medium",
        "description": "Twilio Account SID",
        "fix_prompt_template": (
            "A Twilio Account SID was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "FIX REQUIRED:\n"
            "1. The SID alone is not a secret, but combined with an Auth Token it grants full access.\n"
            "2. Store as `TWILIO_ACCOUNT_SID` environment variable for consistency.\n"
            "3. Ensure the corresponding Auth Token is also in environment variables, never committed.\n"
            "4. Enable Twilio API key rotation and monitor usage logs.\n\n"
            "Rewrite `{file}` to use `os.environ['TWILIO_ACCOUNT_SID']`. "
            "Return the complete corrected file."
        ),
    },
    "private_key": {
        "pattern": re.compile(
            r"-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY"
        ),
        "severity": "high",
        "description": "Private cryptographic key",
        "fix_prompt_template": (
            "CRITICAL: A private cryptographic key was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Consider this private key FULLY COMPROMISED — generate a new key pair immediately.\n"
            "2. Revoke/deregister the old public key from all services (GitHub, servers, cloud APIs).\n"
            "3. Remove the key file from git history with BFG Repo Cleaner or `git filter-branch`.\n"
            "4. Add key file patterns to .gitignore: `*.pem`, `*.key`, `id_rsa`, `id_ed25519`.\n"
            "5. Store private keys as environment variables (base64-encoded) or use a secrets "
            "manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager).\n\n"
            "Rewrite `{file}` to load the key from environment or a secrets manager path. "
            "Return the complete corrected file."
        ),
    },
    "openai_key": {
        "pattern": re.compile(r"sk-[A-Za-z0-9]{48}"),
        "severity": "high",
        "description": "OpenAI API key",
        "fix_prompt_template": (
            "SECURITY INCIDENT: An OpenAI API key was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Immediately revoke the key at https://platform.openai.com/api-keys.\n"
            "2. Check your OpenAI usage dashboard for unexpected API calls.\n"
            "3. Store the key as `OPENAI_API_KEY` environment variable.\n"
            "4. Set spending limits and usage alerts in your OpenAI account.\n"
            "5. Use organisation-level API keys with restricted scopes where possible.\n\n"
            "Rewrite `{file}` to use `os.environ['OPENAI_API_KEY']`. "
            "Return the complete corrected file."
        ),
    },
    "anthropic_key": {
        "pattern": re.compile(r"sk-ant-[A-Za-z0-9\-_]{90,}"),
        "severity": "high",
        "description": "Anthropic API key",
        "fix_prompt_template": (
            "SECURITY INCIDENT: An Anthropic API key was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Revoke the key at https://console.anthropic.com/settings/keys.\n"
            "2. Review usage logs for unauthorised model calls.\n"
            "3. Store as `ANTHROPIC_API_KEY` environment variable.\n"
            "4. Set usage limits and budget alerts in the Anthropic console.\n\n"
            "Rewrite `{file}` to use `os.environ['ANTHROPIC_API_KEY']`. "
            "Return the complete corrected file."
        ),
    },
    "discord_token": {
        "pattern": re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
        "severity": "high",
        "description": "Discord bot token",
        "fix_prompt_template": (
            "A Discord bot token was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Regenerate the token at https://discord.com/developers/applications > Bot > Reset Token.\n"
            "2. Store as `DISCORD_BOT_TOKEN` environment variable.\n"
            "3. Review your bot's audit log for any unauthorised actions.\n"
            "4. Restrict bot permissions to only what is needed (principle of least privilege).\n\n"
            "Rewrite `{file}` to use `os.environ['DISCORD_BOT_TOKEN']`. "
            "Return the complete corrected file."
        ),
    },
    "npm_token": {
        "pattern": re.compile(r"npm_[A-Za-z0-9]{36}"),
        "severity": "high",
        "description": "NPM access token",
        "fix_prompt_template": (
            "An NPM access token was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Revoke the token at https://www.npmjs.com/settings/tokens.\n"
            "2. Check npm audit logs for unauthorised package publishes.\n"
            "3. Store as `NPM_TOKEN` environment variable. In CI use `NPM_TOKEN` secret.\n"
            "4. Use granular access tokens (read-only or publish-only scoped to specific packages).\n"
            "5. Enable two-factor authentication for npm publish operations.\n\n"
            "Rewrite `{file}` to use `os.environ['NPM_TOKEN']`. "
            "Return the complete corrected file."
        ),
    },
    "azure_storage": {
        "pattern": re.compile(r"(?i)AccountKey=[A-Za-z0-9/+=]{88}"),
        "severity": "high",
        "description": "Azure Storage account key",
        "fix_prompt_template": (
            "SECURITY INCIDENT: An Azure Storage account key was found in `{file}` "
            "line {line}. Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Rotate the key in Azure Portal > Storage Account > Access keys > Rotate key.\n"
            "2. Use Azure Key Vault to store and rotate storage keys automatically.\n"
            "3. Prefer Azure Managed Identity and SAS tokens over account keys where possible.\n"
            "4. Store the connection string as `AZURE_STORAGE_CONNECTION_STRING` env variable.\n"
            "5. Enable Azure Monitor alerts for storage access anomalies.\n\n"
            "Rewrite `{file}` to use `os.environ['AZURE_STORAGE_CONNECTION_STRING']`. "
            "Return the complete corrected file."
        ),
    },
    "generic_password": {
        "pattern": re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"]'
            r'(?!.*?(?:REDACTED|example|placeholder|changeme|your_|<|\*|dummy|test|fake|123|abc))'
            r'[^\'"]{8,}[\'"]'
        ),
        "severity": "high",
        "description": "Hardcoded password",
        "fix_prompt_template": (
            "A hardcoded password was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Change this password immediately wherever it is used.\n"
            "2. Move to an environment variable: `os.environ['SERVICE_PASSWORD']`.\n"
            "3. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager) for production.\n"
            "4. Never store passwords in source code — audit git history for past exposures.\n"
            "5. Enforce a git pre-commit hook (gitleaks, truffleHog) to prevent future leaks.\n\n"
            "Rewrite `{file}` to load the password from environment. "
            "Return the complete corrected file."
        ),
    },
    "generic_api_key": {
        "pattern": re.compile(
            r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|client[_\-]?secret|access[_\-]?token)'
            r'\s*[=:]\s*["\']'
            r'(?!.*?(?:REDACTED|example|placeholder|your_|<|\*|dummy|test|undefined|null))'
            r'[A-Za-z0-9_\-\/+=]{12,}["\']'
        ),
        "severity": "high",
        "description": "Hardcoded API key / secret",
        "fix_prompt_template": (
            "A hardcoded API key or secret was found in `{file}` line {line}. "
            "Preview: `{preview}`\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Identify which service this key belongs to and revoke/rotate it immediately.\n"
            "2. Move to an appropriately named environment variable "
            "(e.g. `SERVICE_NAME_API_KEY`).\n"
            "3. Add the variable to `.env.example` with an empty/placeholder value.\n"
            "4. Install a pre-commit secret scanner (gitleaks, detect-secrets) to prevent recurrence.\n"
            "5. Audit git history: `git log -S 'key_value' --source --all`.\n\n"
            "Rewrite `{file}` to load the key from environment variables. "
            "Return the complete corrected file."
        ),
    },
}

# ---------------------------------------------------------------------------
# Sensitive file patterns (committed credential files)
# ---------------------------------------------------------------------------

SENSITIVE_FILE_PATTERNS: list[tuple[str, str, str]] = [
    ("*.pem",                    "high",   "PEM certificate/key file committed"),
    ("*.key",                    "high",   "Private key file committed"),
    ("*.pfx",                    "high",   "PKCS12 bundle committed"),
    ("*.jks",                    "high",   "Java KeyStore committed"),
    ("id_rsa",                   "high",   "SSH private key committed"),
    ("id_dsa",                   "high",   "SSH private key committed"),
    ("id_ed25519",               "high",   "SSH private key committed"),
    (".env",                     "high",   ".env file with credentials committed"),
    (".env.local",               "high",   ".env.local committed"),
    (".env.production",          "high",   ".env.production committed"),
    (".env.staging",             "high",   ".env.staging committed"),
    (".env.development",         "medium", ".env.development committed"),
    ("serviceAccountKey.json",   "high",   "Firebase service account committed"),
    ("service-account*.json",    "high",   "GCP service account committed"),
    ("google-services.json",     "high",   "Firebase google-services.json committed"),
    ("GoogleService-Info.plist", "high",   "Firebase iOS config committed"),
    ("credentials.json",         "high",   "Credentials file committed"),
    ("secrets.json",             "high",   "Secrets file committed"),
    (".netrc",                   "high",   ".netrc credentials committed"),
]

# Safe files that intentionally hold placeholder values
SAFE_FILES: frozenset[str] = frozenset({
    ".env.example", ".env.sample", ".env.template",
    ".env.test", ".env.ci", ".env.schema",
})

IGNORED_DIRS: frozenset[str] = frozenset({
    ".git", ".next", "__pycache__", "node_modules",
    ".venv", "venv", "dist", "build", "coverage",
})

SCANNABLE_EXTS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml",
    ".sh", ".toml", ".cfg", ".ini", ".conf", ".rb", ".go", ".java",
    ".cs", ".php", ".tf", ".tfvars", ".xml", ".txt", ".md", ".env",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_secrets(repo_path: Path) -> list[dict[str, Any]]:
    """
    Scan *repo_path* for exposed secrets and sensitive files.

    Returns a list of findings with shape:
    {
        "id":          int,
        "source":      "code",
        "type":        str,           # e.g. "aws_access_key"
        "severity":    "high" | "medium" | "low",
        "description": str,
        "file":        str,           # relative path
        "line":        int | None,
        "preview":     str,           # masked — actual secret replaced with ***
        "fix_types":   ["move_to_env"],
        "fixable":     bool,
    }
    """
    findings: list[dict[str, Any]] = []
    fid = 1

    # Pass 1: sensitive committed files
    for fp in repo_path.rglob("*"):
        if fp.is_dir() or _ignored(fp, repo_path):
            continue
        if fp.name in SAFE_FILES:
            continue
        m = _match_file(fp.name)
        if m:
            sev, desc = m
            findings.append({
                "id": fid, "source": "code", "type": "sensitive_file",
                "severity": sev, "description": desc,
                "file": str(fp.relative_to(repo_path)), "line": None,
                "preview": f"Sensitive file: {fp.name}",
                "fix_types": ["move_to_env"], "fixable": True,
            })
            fid += 1

    # Pass 2: content-level secret patterns
    seen: set[tuple[str, str, int]] = set()
    for fp in repo_path.rglob("*"):
        if fp.is_dir() or _ignored(fp, repo_path):
            continue
        if fp.name in SAFE_FILES:
            continue
        is_env = fp.name.startswith(".env")
        if not is_env and fp.suffix.lower() not in SCANNABLE_EXTS:
            continue
        try:
            if fp.stat().st_size > 500_000:
                continue
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = str(fp.relative_to(repo_path))
        for stype, cfg in SECRET_PATTERNS.items():
            for lnum, line in enumerate(content.splitlines(), 1):
                key = (rel, stype, lnum)
                if key in seen:
                    continue
                match = cfg["pattern"].search(line)
                if match:
                    raw = match.group(0)
                    findings.append({
                        "id": fid, "source": "code", "type": stype,
                        "severity": cfg["severity"], "description": cfg["description"],
                        "file": rel, "line": lnum,
                        "preview": line.strip()[:200].replace(raw, _mask(raw)),
                        "fix_types": ["move_to_env"], "fixable": True,
                    })
                    fid += 1
                    seen.add(key)
                    break

    logger.info("secret_scanner: %d findings", len(findings))
    return findings


def get_secret_fix_prompt(finding: dict[str, Any], file_content: str = "") -> str:
    """
    Build a deep-research LLM prompt for a secret/credential finding.

    Uses the ``fix_prompt_template`` registered in SECRET_PATTERNS for
    this secret type, appending the file content when available so the
    LLM can return a completely corrected file.

    Args:
        finding:      A finding dict as returned by scan_secrets().
        file_content: Current source code of the affected file (optional).

    Returns:
        A ready-to-send prompt string with full remediation context.
    """
    secret_type = finding.get("type", "unknown")
    cfg = SECRET_PATTERNS.get(secret_type, {})

    # Sensitive-file findings have no content template — build a generic one
    if secret_type == "sensitive_file" or secret_type not in SECRET_PATTERNS:
        template = (
            "A sensitive file (`{file}`) containing credentials was committed to the repository. "
            "Description: {description}\n\n"
            "DEEP RESEARCH FIX REQUIRED:\n"
            "1. Remove this file from the repository and all git history.\n"
            "2. Add it to .gitignore immediately.\n"
            "3. Rotate any credentials the file contained.\n"
            "4. If this file is needed for configuration, use environment variables or a "
            "secrets manager instead of committing the file.\n\n"
            "Provide the corrected .gitignore and any relevant configuration files."
        )
    else:
        template = cfg.get(
            "fix_prompt_template",
            (
                "A secret of type '{type}' ({description}) was found in `{file}` line {line}.\n"
                "Preview: `{preview}`\n\n"
                "TASK: Remove the hardcoded secret, rotate it at the source service, and "
                "replace it with an environment variable. Return the corrected file."
            ),
        )

    intro = template.format(
        file=finding.get("file", "unknown"),
        line=finding.get("line", "?"),
        preview=finding.get("preview", ""),
        description=finding.get("description", secret_type),
        type=secret_type,
    )

    if not file_content:
        return intro

    return (
        f"{intro}\n\n"
        "---\n"
        f"Current file content (`{finding.get('file', '')}`):\n"
        "```\n"
        f"{file_content}\n"
        "```\n\n"
        "Return ONLY the corrected, complete file content — no explanations, "
        "no markdown fences, no truncation. "
        "Replace every hardcoded secret with the appropriate os.environ / process.env call."
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ignored(fp: Path, root: Path) -> bool:
    try:
        return any(p in IGNORED_DIRS for p in fp.relative_to(root).parts)
    except ValueError:
        return True


def _match_file(name: str) -> tuple[str, str] | None:
    if name in SAFE_FILES:
        return None
    for pat, sev, desc in SENSITIVE_FILE_PATTERNS:
        if fnmatch.fnmatch(name, pat):
            return sev, desc
    return None


def _mask(s: str) -> str:
    return f"{s[:4]}{'*' * min(len(s) - 8, 10)}{s[-4:]}" if len(s) > 8 else "***"
