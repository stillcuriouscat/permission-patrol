#!/usr/bin/env python3
"""
Auto Whitelist Domain Hook for Claude Code
===========================================
This script runs as a PostToolUse hook. After a WebFetch succeeds,
it automatically adds the domain to the trusted domains whitelist.

This way, users only need to approve once, and future requests to
the same domain will be auto-approved.
"""

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

# Whitelist file path
TRUSTED_DOMAINS_FILE = Path(__file__).parent / "trusted-domains.txt"


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def load_trusted_domains() -> set:
    """Load existing trusted domains."""
    domains = set()
    if TRUSTED_DOMAINS_FILE.exists():
        for line in TRUSTED_DOMAINS_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.add(line.lower())
    return domains


def add_domain_to_whitelist(domain: str) -> bool:
    """Add domain to whitelist."""
    try:
        # Ensure file exists
        if not TRUSTED_DOMAINS_FILE.exists():
            TRUSTED_DOMAINS_FILE.parent.mkdir(parents=True, exist_ok=True)
            TRUSTED_DOMAINS_FILE.write_text("# Trusted domains whitelist\n")

        # Append domain
        with open(TRUSTED_DOMAINS_FILE, "a") as f:
            f.write(f"\n{domain}")

        return True
    except Exception:
        return False


def main():
    # Read JSON input from stdin
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_name = request.get("tool_name", "")

    # Only handle WebFetch
    if tool_name != "WebFetch":
        sys.exit(0)

    # Extract URL and domain
    tool_input = request.get("tool_input", {})
    url = tool_input.get("url", "")
    domain = extract_domain(url)

    if not domain:
        sys.exit(0)

    # Check if already in whitelist
    existing_domains = load_trusted_domains()
    if domain in existing_domains:
        sys.exit(0)

    # Check if parent domain is already in whitelist
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        parent_domain = ".".join(parts[i:])
        if parent_domain in existing_domains:
            sys.exit(0)

    # Add to whitelist
    if add_domain_to_whitelist(domain):
        # Output systemMessage to notify user
        output = {
            "systemMessage": f"✅ Added {domain} to trusted domains whitelist"
        }
        print(json.dumps(output))

    sys.exit(0)


if __name__ == "__main__":
    main()
