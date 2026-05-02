from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


@dataclass(slots=True)
class Settings:
    # ── GitHub ──────────────────────────────────────────────────────────────
    github_token: str = os.getenv("GITHUB_TOKEN", "")

    # ── LLM Providers (priority: Claude > Gemini > Groq) ───────────────────
    claude_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    claude_model: str = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    # ── Optional integrations ───────────────────────────────────────────────
    hf_api_key: str = os.getenv("HF_API_KEY", "")

    # ── CORS (production: set to your actual frontend domain) ───────────────
    # FRONTEND_ORIGIN accepts comma-separated URLs, e.g.:
    #   FRONTEND_ORIGIN=https://opendev.example.com,https://www.opendev.example.com
    # FRONTEND_ORIGIN_REGEX accepts a regex, e.g.:
    #   FRONTEND_ORIGIN_REGEX=https://.*\.vercel\.app
    # At least one of these must be set for production deployments.
    frontend_origin: str = os.getenv("FRONTEND_ORIGIN", "")
    frontend_origin_regex: str = os.getenv("FRONTEND_ORIGIN_REGEX", "")

    # ── Git identity for commits ────────────────────────────────────────────
    git_author_name: str = os.getenv("GIT_AUTHOR_NAME", "OpenDev AI")
    git_author_email: str = os.getenv(
        "GIT_AUTHOR_EMAIL",
        "opendev-ai@users.noreply.github.com",
    )

    # ── Operational tuning ──────────────────────────────────────────────────
    command_timeout_seconds: int = int(os.getenv("COMMAND_TIMEOUT_SECONDS", "300"))

    # ── Derived properties ──────────────────────────────────────────────────

    @property
    def missing_github(self) -> list[str]:
        return [name for name, value in {"GITHUB_TOKEN": self.github_token}.items() if not value]

    @property
    def has_llm_provider(self) -> bool:
        return bool(self.claude_api_key or self.gemini_api_key or self.groq_api_key)

    @property
    def active_llm_provider(self) -> str:
        """Return the name of the first available LLM provider (priority order)."""
        if self.claude_api_key:
            return "claude"
        if self.gemini_api_key:
            return "gemini"
        if self.groq_api_key:
            return "groq"
        return "none"

    @property
    def frontend_origins(self) -> list[str]:
        """Parse FRONTEND_ORIGIN into a list. Empty string = no explicit origin list."""
        return [o.strip() for o in self.frontend_origin.split(",") if o.strip()]


settings = Settings()
