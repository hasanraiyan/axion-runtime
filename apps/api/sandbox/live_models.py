"""Standalone live-model probe — paste a key, get the provider's real JSON back.

Deliberately self-contained: no settings, no MongoDB, no Clerk, no imports from
`app/`. Run it from a terminal whenever you need to know what a provider really
reports for its models (token limits, temperature, capabilities) instead of
guessing or trusting a second-hand copy.

    cd apps/api
    .\\.venv\\Scripts\\python.exe sandbox\\live_models.py
    .\\.venv\\Scripts\\python.exe sandbox\\live_models.py --provider google_genai --key AIza...

Edit the CONFIG block below, or pass --provider / --key / --base-url / --out.
The raw response body is written as JSON under `sandbox/out/` (git-ignored);
the API key itself is never written to the file and the query string is stripped.

SECURITY: this file is a scratchpad. Keep it out of commits (or blank out the
key) before pushing anywhere public.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

# --------------------------------------------------------------------------
# CONFIG — put your key here for quick testing
# --------------------------------------------------------------------------
PROVIDER = "google_genai"  # openai | google_genai | anthropic | custom
API_KEY = os.environ.get("PROBE_API_KEY", "PASTE-YOUR-API-KEY-HERE")
BASE_URL: Optional[str] = None  # required for "custom"; optional override otherwise
CUSTOM_HEADERS: Dict[str, str] = {}  # e.g. {"HTTP-Referer": "https://..."} for OpenRouter

OUTPUT_DIR = Path(__file__).resolve().parent / "out"
TIMEOUT_SECONDS = 30


def build_request(provider: str, api_key: str, base_url: Optional[str]) -> tuple[str, Dict[str, str]]:
    headers: Dict[str, str] = dict(CUSTOM_HEADERS)
    if provider in ("openai", "custom"):
        base = (base_url or "https://api.openai.com/v1").rstrip("/")
        headers.setdefault("Authorization", f"Bearer {api_key}")
        return f"{base}/models", headers
    if provider == "google_genai":
        headers.setdefault("Content-Type", "application/json")
        return f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}", headers
    if provider == "anthropic":
        base = (base_url or "https://api.anthropic.com/v1").rstrip("/")
        headers.setdefault("x-api-key", api_key)
        headers.setdefault("anthropic-version", "2023-06-01")
        return f"{base}/models", headers
    raise SystemExit(f"Unknown provider '{provider}'. Use openai | google_genai | anthropic | custom.")


def redact_url(url: str) -> str:
    """Never persist the key: Google passes it as `?key=`."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch a provider's live model list and save the raw JSON.")
    parser.add_argument("--provider", default=PROVIDER, help="openai | google_genai | anthropic | custom")
    parser.add_argument("--key", default=API_KEY, help="API key (defaults to the CONFIG block / PROBE_API_KEY)")
    parser.add_argument("--base-url", default=BASE_URL, help="Override the endpoint base (required for custom)")
    parser.add_argument("--out", default=None, help="Output file or directory (default: sandbox/out)")
    args = parser.parse_args()

    if not args.key or args.key == "PASTE-YOUR-API-KEY-HERE":
        raise SystemExit("Set API_KEY in the CONFIG block (or pass --key, or PROBE_API_KEY).")

    url, headers = build_request(args.provider, args.key, args.base_url)

    with httpx.Client(timeout=TIMEOUT_SECONDS) as client:
        try:
            response = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            print(f"request failed: {type(exc).__name__}: {exc}")
            return 2

    try:
        payload: Any = response.json()
    except ValueError:
        payload = {"body": response.text}

    captured_at = datetime.now(timezone.utc)
    record = {
        "captured_at": captured_at.isoformat(),
        "provider": args.provider,
        "endpoint": redact_url(url),
        "http_status": response.status_code,
        "payload": payload,
    }

    if args.out:
        out = Path(args.out)
        target = out if out.suffix.lower() == ".json" else out / f"{args.provider}_live_models_{captured_at:%Y%m%dT%H%M%SZ}.json"
    else:
        target = OUTPUT_DIR / f"{args.provider}_live_models_{captured_at:%Y%m%dT%H%M%SZ}.json"

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    models = []
    if isinstance(payload, dict):
        models = payload.get("data") or payload.get("models") or []
    elif isinstance(payload, list):
        models = payload

    print(f"HTTP {response.status_code} — {len(models)} models")
    print(f"saved: {target}")
    if response.status_code >= 400:
        print(json.dumps(payload, indent=2, ensure_ascii=False)[:2000])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
