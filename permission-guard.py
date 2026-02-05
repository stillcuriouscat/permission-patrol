#!/usr/bin/env python3
"""
Permission Guard Hook for Claude Code
======================================
This script runs as a PermissionRequest hook, using Opus 4.5 to review permission requests.

Security Policy:
- Delete operations: Deny
- Upload operations: Deny
- Access paths outside project: Ask user
- Trusted domains: Auto-approve
- Other cases: Call Opus for review
"""

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

# ============================================================================
# Configuration
# ============================================================================

# Whitelist file path (auto-grows over time)
TRUSTED_DOMAINS_FILE = Path(__file__).parent / "trusted-domains.txt"

# Sensitive path patterns (accessing these requires user confirmation)
SENSITIVE_PATHS = [
    r"^/etc/",
    r"^/root/",
    r"^~/.ssh/",
    r"^~/.gnupg/",
    r"^~/.aws/",
    r"^~/.config/gcloud/",
    r"\.env$",
    r"credentials",
    r"secrets?\.ya?ml$",
    r"\.pem$",
    r"\.key$",
]

# Dangerous command patterns (directly denied)
DANGEROUS_PATTERNS = [
    # Delete operations
    r"\brm\s+(-[rfRvid]+\s+)*(/|~|/home)",  # rm targeting root or home
    r"\bunlink\s+",
    r"\bshred\s+",
    # Upload operations
    r"\bcurl\s+.*(-X\s*POST|-d\s|--data|--upload-file|-F\s|--form)",
    r"\bwget\s+.*--post",
    r"\bscp\s+[^:]+\s+\S+:",  # scp to remote
    r"\brsync\s+.*\s+\S+:",   # rsync to remote
    # System destruction
    r"\bmkfs\b",
    r"\bdd\s+.*of=/dev/",
    r"\bchmod\s+777\s+/",
    r"\bchown\s+.*\s+/",
    # Reverse shell
    r"\bnc\s+.*-e\s+",
    r"\bbash\s+-i\s+",
    r"/dev/tcp/",
]

# Dangerous patterns in code (reference for Opus review)
CODE_DANGER_PATTERNS = [
    r"os\.remove",
    r"os\.unlink",
    r"shutil\.rmtree",
    r"pathlib\.Path.*\.unlink",
    r"requests\.(post|put|patch)",
    r"urllib.*urlopen.*data=",
    r"subprocess.*rm\s",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__",
]


# ============================================================================
# Utility Functions
# ============================================================================

def load_trusted_domains() -> set:
    """Load trusted domain whitelist."""
    domains = set()
    if TRUSTED_DOMAINS_FILE.exists():
        for line in TRUSTED_DOMAINS_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.add(line.lower())
    return domains


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def is_path_in_project(path: str, cwd: str, additional_dirs: list) -> bool:
    """Check if path is within project scope."""
    try:
        # Expand ~ and environment variables
        path = os.path.expanduser(os.path.expandvars(path))
        path = os.path.abspath(path)

        # Check if under cwd
        if path.startswith(os.path.abspath(cwd)):
            return True

        # Check if under additionalDirectories
        for add_dir in additional_dirs:
            add_dir = os.path.expanduser(os.path.expandvars(add_dir))
            add_dir = os.path.abspath(add_dir)
            if path.startswith(add_dir):
                return True

        return False
    except Exception:
        return False


def is_sensitive_path(path: str) -> bool:
    """Check if path is sensitive."""
    path = os.path.expanduser(path)
    for pattern in SENSITIVE_PATHS:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    return False


def is_dangerous_command(command: str) -> tuple[bool, str]:
    """Check if command contains dangerous patterns."""
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True, f"Dangerous pattern detected: {pattern}"
    return False, ""


def has_code_danger_patterns(code: str) -> list:
    """Check if code contains dangerous patterns."""
    found = []
    for pattern in CODE_DANGER_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            found.append(pattern)
    return found


# ============================================================================
# Opus API Review
# ============================================================================

def call_opus_for_review(request: dict) -> dict:
    """Call Opus 4.5 for intelligent security review."""
    try:
        import anthropic
    except ImportError:
        # If anthropic not installed, skip Opus review
        return {"decision": "ask", "reason": "anthropic SDK not installed, cannot perform intelligent review"}

    tool_name = request.get("tool_name", "Unknown")
    tool_input = request.get("tool_input", {})
    cwd = request.get("cwd", "")

    # Build review prompt
    prompt = f"""You are a security reviewer for Claude Code. Analyze the following permission request and determine if it should be auto-approved.

## Request Information
- Tool: {tool_name}
- Working Directory: {cwd}
- Parameters:
```json
{json.dumps(tool_input, indent=2, ensure_ascii=False)}
```

## Security Checklist
1. **Delete operations**: Will it delete files/directories? (including os.remove, shutil.rmtree in code)
2. **Upload/Send data**: Will it send data externally? (POST requests, scp, rsync to remote, etc.)
3. **Sensitive paths**: Does it access ~/.ssh, ~/.gnupg, .env, credentials, etc.?
4. **Command injection**: Are there suspicious semicolons, backticks, $() that could be injection attacks?
5. **Path traversal**: Are there ../../ path traversal attack patterns?

## Decision Criteria
- If it's **clearly a normal development operation** (reading files, git operations, running tests) → allow
- If there's **any security risk** but uncertain if malicious → ask (let user confirm)
- If it's **clearly dangerous/malicious** → deny

## Response Format (pure JSON, no other text)
{{"decision": "allow"}}
or {{"decision": "ask", "reason": "reason for confirmation"}}
or {{"decision": "deny", "reason": "reason for denial"}}
"""

    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model="claude-opus-4-5-20250929",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        # Extract text content
        text = response.content[0].text.strip()

        # Try to parse JSON (may be wrapped in markdown)
        if "```" in text:
            # Extract content between ```
            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match:
                text = match.group(1)

        result = json.loads(text)
        return result

    except json.JSONDecodeError:
        return {"decision": "ask", "reason": "Could not parse Opus response"}
    except anthropic.APIError as e:
        return {"decision": "ask", "reason": f"Opus API error: {e}"}
    except Exception as e:
        return {"decision": "ask", "reason": f"Review error: {e}"}


# ============================================================================
# Output Functions
# ============================================================================

def allow():
    """Approve the request."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"}
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def deny(reason: str):
    """Deny the request."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": reason
            }
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def ask_user():
    """Let user decide (don't return decision)."""
    # exit 0 without outputting decision, Claude Code will show standard permission dialog
    sys.exit(0)


# ============================================================================
# Main Logic
# ============================================================================

def main():
    # 1. Read JSON input from stdin
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Cannot parse input, let user decide
        ask_user()
        return

    tool_name = request.get("tool_name", "")
    tool_input = request.get("tool_input", {})
    cwd = request.get("cwd", "")

    # Read additionalDirectories from settings.json
    additional_dirs = []
    settings_path = Path.home() / ".claude" / "settings.json"
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
            additional_dirs = settings.get("permissions", {}).get("additionalDirectories", [])
        except Exception:
            pass

    # ========================================================================
    # 2. Quick check: Dangerous commands (directly deny)
    # ========================================================================

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        is_dangerous, reason = is_dangerous_command(command)
        if is_dangerous:
            deny(f"⛔ {reason}")
            return

    # ========================================================================
    # 3. WebFetch: Domain whitelist check
    # ========================================================================

    if tool_name == "WebFetch":
        url = tool_input.get("url", "")
        domain = extract_domain(url)
        trusted_domains = load_trusted_domains()

        # Check if domain is in whitelist (including subdomains)
        if domain in trusted_domains:
            allow()
            return

        # Check if parent domain is in whitelist
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            parent_domain = ".".join(parts[i:])
            if parent_domain in trusted_domains:
                allow()
                return

        # Domain not in whitelist, let user confirm
        # (If user approves, PostToolUse hook will auto-add domain to whitelist)
        ask_user()
        return

    # ========================================================================
    # 4. Path check: Is it within project scope?
    # ========================================================================

    # Extract paths from tool_input
    paths_to_check = []
    if "file_path" in tool_input:
        paths_to_check.append(tool_input["file_path"])
    if "path" in tool_input:
        paths_to_check.append(tool_input["path"])

    # Bash commands may contain paths
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        # Simple path extraction (strings starting with / or ~)
        path_matches = re.findall(r'(?:^|\s)([~/][^\s;|&<>]+)', command)
        paths_to_check.extend(path_matches)

    for path in paths_to_check:
        # Check sensitive paths
        if is_sensitive_path(path):
            ask_user()  # Let user confirm
            return

        # Check if within project scope
        if not is_path_in_project(path, cwd, additional_dirs):
            ask_user()  # Let user confirm
            return

    # ========================================================================
    # 5. Call Opus for intelligent review
    # ========================================================================

    # For code execution, first check for dangerous patterns in code
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        # If running Python/Node scripts, need deeper inspection
        if re.search(r'\b(python|python3|node|bash|sh)\s+', command):
            result = call_opus_for_review(request)
            decision = result.get("decision", "ask")
            reason = result.get("reason", "")

            if decision == "allow":
                allow()
            elif decision == "deny":
                deny(f"⛔ Opus review denied: {reason}")
            else:
                ask_user()
            return

    # For Write/Edit operations, check if content contains dangerous code
    if tool_name in ("Write", "Edit"):
        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        danger_patterns = has_code_danger_patterns(content)
        if danger_patterns:
            result = call_opus_for_review(request)
            decision = result.get("decision", "ask")
            reason = result.get("reason", "")

            if decision == "allow":
                allow()
            elif decision == "deny":
                deny(f"⛔ Opus review denied: {reason}")
            else:
                ask_user()
            return

    # ========================================================================
    # 6. Default: Let user decide
    # ========================================================================

    # For cases not explicitly handled, let user decide
    ask_user()


if __name__ == "__main__":
    main()
