<div align="center">

# OpenDev AI

**Autonomous GitHub maintenance agent powered by LLMs + Reinforcement Learning**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)](https://www.python.org/)
[![Next.js 14](https://img.shields.io/badge/Next.js-14-black?style=flat-square)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?style=flat-square)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

## Overview

OpenDev AI is an autonomous software maintenance platform that connects to any GitHub repository and performs:

- **Security scanning** — 25+ vulnerability patterns (OWASP Top 10, secrets, misconfigurations)
- **Automated issue fixing** — forks the repo, applies an LLM-generated patch, runs tests, opens a PR
- **Pull request review** — AI-powered analysis with MERGE / REQUEST\_CHANGES / COMMENT recommendations
- **Duplicate-safe issue creation** — opens labelled GitHub issues with remediation guidance

Everything is observable in real-time through a live log terminal in the browser UI.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser (Next.js 14)                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ Analyze  │ │  Issues  │ │   Scan   │ │   PR Review      │  │
│  │  page    │ │   page   │ │   page   │ │   page           │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬─────────┘  │
│       └────────────┴────────────┴─────────────────┘            │
│                        lib/api.ts (fetch)                       │
│            NEXT_PUBLIC_API_URL from environment                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP / REST
┌──────────────────────────▼──────────────────────────────────────┐
│                    FastAPI Backend (Python 3.11)                 │
│                                                                  │
│  ┌─────────────┐  ┌───────────────┐  ┌─────────────────────┐  │
│  │  agent.py   │  │  scanner.py   │  │  github_service.py  │  │
│  │ orchestrator│  │ 25+ vuln types│  │  PyGithub wrapper   │  │
│  └──────┬──────┘  └───────┬───────┘  └──────────┬──────────┘  │
│         │                 │                       │              │
│  ┌──────▼──────────────────▼───────────────────────▼─────────┐ │
│  │                      llm.py                                │ │
│  │        Claude (Anthropic)  →  Gemini  →  Groq              │ │
│  │        Priority fallback chain with latency logging        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │  rl_agent  │  │   executor   │  │   secret_scanner     │   │
│  │ Q-learning │  │  CommandRun  │  │  40+ secret patterns │   │
│  └────────────┘  └──────────────┘  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                           │
                 GitHub API (PyGithub)
```

---

## LLM Provider Chain

| Priority | Provider | Model | Env Variable |
|----------|----------|-------|--------------|
| 1 | **Anthropic Claude** | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` |
| 2 | **Google Gemini** | `gemini-2.0-flash` | `GEMINI_API_KEY` |
| 3 | **Groq (Llama 3)** | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |

The system tries Claude first; if the key is absent or the call fails, it automatically falls back to Gemini, then Groq. Every attempt is logged with provider name and latency in milliseconds.

---

## Security Scanning

### Vulnerability Detection (25+ types)

| Category | Types Detected |
|----------|---------------|
| Injection | SQL, NoSQL, LDAP, Command, Template (SSTI) |
| XSS | `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html` |
| Code Execution | `eval()`, `exec()`, `new Function()`, pickle/yaml deserialization |
| Web Security | SSRF, Open redirect, XXE, CORS misconfiguration, Prototype pollution |
| Authentication | JWT bypass, Missing auth checks, IDOR, Insecure cookies |
| Data | Path traversal, Mass assignment, Race conditions, File upload |
| Cryptography | MD5/SHA1, `Math.random()` for crypto, DES |
| Configuration | Debug mode in production, Hardcoded credentials |

### Secret / Credential Detection (40+ patterns)

AWS keys, GitHub tokens, Stripe keys, Firebase configs, MongoDB URIs, private keys, OpenAI/Anthropic API keys, and 30+ more.

### Security Scoring

Scores are calculated using a **deduction-based system** starting from 100:

| Severity | Points Deducted per Finding |
|----------|-----------------------------|
| High | −15 |
| Medium | −8 |
| Low | −3 |

**Grade scale:** A (90–100) · B (75–89) · C (60–74) · D (40–59) · F (0–39)

**Scanned:** `.py`, `.js`, `.ts`, `.tsx`, `.jsx`, `.php`, `.rb`, `.java`, `.go`, `.cs`, `.sh` — files under 500 KB, excluding `node_modules`, `.git`, `dist`, `build`.

---

## Fix Pipeline

When fixing a GitHub issue, the agent follows this pipeline:

```
1. Clone repo  →  2. LLM generates patch  →  3. Patch safety checks
       ↓
4. Apply patch  →  5. Run tests (npm/pytest)  →  6. Generate diff
       ↓
7. Human reviews diff + test results  →  8. Approve  →  9. Push + open PR
```

### Patch Safety Checks (pre-apply)

| Check | Action |
|-------|--------|
| Delete `package.json`, `Dockerfile`, etc. | **Block** — raises error |
| Patch removes > 60% of file lines | **Warn** — log + continue |
| Patch removes > 3 import statements | **Warn** — log + continue |
| Path traversal in file path | **Block** — raises error |

### Automated Test Execution (post-apply)

| Stack Detected | Command |
|----------------|---------|
| Node.js (`package.json` with `scripts.test`) | `npm install && npm test` |
| Python (`pytest.ini`, `pyproject.toml`, `setup.py`) | `pytest` |
| None detected | Skipped (noted in result) |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- GitHub Personal Access Token (`repo` scope)
- At least one LLM provider API key

### 1. Backend

```bash
git clone https://github.com/DEVIDAS-CHINNARATHOD/OpenDev-AI.git
cd OpenDev-AI/backend

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # fill in your keys
uvicorn main:app --reload --port 8000
```

### 2. Frontend

```bash
cd ../frontend
npm install
cp .env.local.example .env.local  # set NEXT_PUBLIC_API_URL
npm run dev                        # open http://localhost:3000
```

---

## Environment Variables

### Backend (`backend/.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Yes | GitHub PAT with `repo` scope |
| `GIT_AUTHOR_NAME` | Yes | Commit author name |
| `GIT_AUTHOR_EMAIL` | Yes | Commit author email |
| `ANTHROPIC_API_KEY` | One LLM required | Claude API key (highest priority) |
| `CLAUDE_MODEL` | No | Default: `claude-sonnet-4-20250514` |
| `GEMINI_API_KEY` | One LLM required | Google Gemini API key |
| `GEMINI_MODEL` | No | Default: `gemini-2.0-flash` |
| `GROQ_API_KEY` | One LLM required | Groq API key (fallback) |
| `GROQ_MODEL` | No | Default: `llama-3.3-70b-versatile` |
| `FRONTEND_ORIGIN` | Production | Comma-separated allowed origins, e.g. `https://app.example.com` |
| `FRONTEND_ORIGIN_REGEX` | Production | Regex for dynamic origins, e.g. `https://.*\.vercel\.app` |
| `COMMAND_TIMEOUT_SECONDS` | No | Default: `300` |

### Frontend (`frontend/.env.local`)

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXT_PUBLIC_API_URL` | Yes | Backend URL, e.g. `https://api.example.com` |

---

## Deployment

### Backend (Fly.io / Railway / Render)

```bash
# No localhost defaults exist — all config via env vars
fly deploy                 # or: railway up
```

Required env vars in your platform dashboard:
- `GITHUB_TOKEN`
- At least one LLM key
- `FRONTEND_ORIGIN` set to your production frontend URL

### Frontend (Vercel / Netlify)

Set in your platform's environment settings:

```
NEXT_PUBLIC_API_URL=https://your-backend.fly.dev
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14 · React 18 · TypeScript · Tailwind CSS |
| Backend | FastAPI · Python 3.11 · Uvicorn |
| AI / LLM | Anthropic Claude · Google Gemini · Groq (Llama 3) |
| GitHub | PyGithub · Git CLI |
| Reinforcement Learning | Custom Q-learning agent |

---

## License

MIT — see [LICENSE](LICENSE) for details.
