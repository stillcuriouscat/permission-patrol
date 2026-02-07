#!/usr/bin/env python3
"""
Permission Guard Hook for Claude Code
======================================
This script runs as a PermissionRequest hook, using Claude CLI (Opus) to review permission requests.
Uses subscription quota via CLI - no separate API key required.

Security Architecture:
- Phase 0: User-interactive tools (ExitPlanMode, AskUserQuestion) → pass to user
- Phase 1: Dangerous regex patterns → auto deny (no API call)
- Phase 2: Outside project / sensitive paths → Opus review + user confirmation
- Phase 3: Inside project → Opus review, Claude can auto-approve

Key principle: Claude can deny on behalf of the user, but NEVER approve outside-project operations.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Debug log file - use XDG_STATE_HOME or ~/.local/state to avoid /tmp symlink attacks
_state_dir = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "permission-patrol"
_state_dir.mkdir(parents=True, exist_ok=True)
DEBUG_LOG = _state_dir / "permission-guard.log"

def log_debug(msg: str):
    """Write debug message to log file."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    with open(DEBUG_LOG, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

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
    # Reverse shell / data exfiltration
    r"\bnc\s+.*-e\s+",
    r"\bbash\s+-i\s+",
    r"/dev/tcp/",
    r"\|\s*nc\s+\S+\s+\d+",  # pipe to nc (data exfiltration)
    r"\|\s*curl\s+",         # pipe to curl
    r"\|\s*wget\s+",         # pipe to wget
    r"base64.*\|\s*nc\s+",   # base64 encode then send
]

# Dangerous patterns in code (reference for Claude review)
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

def is_path_in_project(path: str, cwd: str, additional_dirs: list) -> bool:
    """Check if path is within project scope."""
    try:
        from pathlib import PurePath
        resolved = PurePath(os.path.abspath(os.path.expanduser(os.path.expandvars(path))))

        # Check if under cwd
        if resolved.is_relative_to(os.path.abspath(cwd)):
            return True

        # Check if under additionalDirectories
        for add_dir in additional_dirs:
            add_dir = os.path.abspath(os.path.expanduser(os.path.expandvars(add_dir)))
            if resolved.is_relative_to(add_dir):
                return True

        return False
    except Exception:
        return False


def is_sensitive_path(path: str) -> bool:
    """Check if path is sensitive."""
    expanded = os.path.expanduser(path)
    # Also construct tilde-relative path (e.g. /home/user/.ssh → ~/.ssh)
    home = os.path.expanduser("~")
    tilde_path = "~" + expanded[len(home):] if expanded.startswith(home) else ""
    return any(
        re.search(p, path, re.IGNORECASE)
        or re.search(p, expanded, re.IGNORECASE)
        or (tilde_path and re.search(p, tilde_path, re.IGNORECASE))
        for p in SENSITIVE_PATHS
    )


def find_dangerous_pattern(command: str) -> str | None:
    """Return the first dangerous pattern found in command, or None."""
    return next(
        (p for p in DANGEROUS_PATTERNS if re.search(p, command, re.IGNORECASE)),
        None,
    )


def has_code_danger_patterns(code: str) -> list:
    """Check if code contains dangerous patterns."""
    return [p for p in CODE_DANGER_PATTERNS if re.search(p, code, re.IGNORECASE)]


# ============================================================================
# Claude CLI Review
# ============================================================================

def call_claude_for_review(request: dict, script_content: str = "") -> dict:
    """Call Claude CLI (Opus) for intelligent security review. Uses subscription quota."""
    tool_name = request.get("tool_name", "Unknown")
    tool_input = request.get("tool_input", {})
    cwd = request.get("cwd", "")

    # Build script content section if provided
    script_section = ""
    if script_content:
        script_section = f"""
## Script Content
```
{script_content}
```
"""

    # Build review prompt
    prompt = f"""You are a security reviewer for Claude Code. Analyze the following permission request and determine if it should be auto-approved.

## Request Information
- Tool: {tool_name}
- Working Directory: {cwd}
- Parameters:
```json
{json.dumps(tool_input, indent=2, ensure_ascii=False)}
```
{script_section}
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

    text = ""  # Initialize for error handling
    try:
        log_debug("Calling Claude CLI (opus)...")

        # Call claude CLI with print mode
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", "opus", "--output-format", "text"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            log_debug(f"CLI error: {result.stderr}")
            return {"decision": "ask", "reason": f"CLI error: {result.stderr}"}

        text = result.stdout.strip()
        log_debug(f"Claude response: {text[:200]}")

        # Try to parse JSON (may be wrapped in markdown)
        if "```" in text:
            # Extract content between ```
            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match:
                text = match.group(1)

        # Find JSON object in response
        json_match = re.search(r'\{[^{}]*"decision"[^{}]*\}', text)
        if json_match:
            text = json_match.group(0)

        parsed = json.loads(text)
        log_debug(f"Claude decision: {parsed}")
        return parsed

    except subprocess.TimeoutExpired:
        log_debug("ERROR: CLI timeout")
        return {"decision": "ask", "reason": "CLI timeout"}
    except json.JSONDecodeError:
        log_debug(f"ERROR: Could not parse response: {text[:100]}")
        return {"decision": "ask", "reason": "Could not parse Claude response"}
    except FileNotFoundError:
        log_debug("ERROR: claude CLI not found")
        return {"decision": "ask", "reason": "claude CLI not found in PATH"}
    except Exception as e:
        log_debug(f"ERROR: Review error: {e}")
        return {"decision": "ask", "reason": f"Review error: {e}"}


def review_request(request: dict, script_content: str = "") -> tuple[str, str]:
    """Call Claude for review and return (decision, reason)."""
    result = call_claude_for_review(request, script_content)
    return result.get("decision", "ask"), result.get("reason", "")


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


def play_notification_sound():
    """Play a notification sound on Linux to alert the user."""
    if not sys.platform.startswith("linux"):
        log_debug("Skipping sound: not Linux")
        return
    try:
        proc = subprocess.Popen(
            ["paplay", "/usr/share/sounds/ubuntu/notifications/Mallet.ogg"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log_debug(f"Sound triggered (pid={proc.pid})")
    except Exception as e:
        log_debug(f"Sound failed: {e}")


def ask_user(context: str = ""):
    """Let user decide (don't return decision).

    Args:
        context: Optional context message explaining why user confirmation is needed.
                 Will be shown via desktop notification and sound alert on Linux.
    """
    # Play notification sound on Linux
    play_notification_sound()

    if context:
        # Send desktop notification on Linux only
        if sys.platform.startswith("linux"):
            try:
                subprocess.run(
                    ["notify-send", "-u", "normal", "-t", "10000",
                     "Permission Patrol", context],
                    capture_output=True,
                    timeout=2
                )
            except Exception:
                pass  # Notification is optional

        log_debug(f"Asking user: {context}")

    # exit 0 without outputting decision, Claude Code will show standard permission dialog
    sys.exit(0)


def handle_claude_decision(decision: str, reason: str):
    """Handle Claude's decision for in-project operations.

    Used only for operations confirmed to be inside the project scope.
    - deny → deny with warning
    - allow → allow
    - ask → ask user
    """
    if decision == "deny":
        deny(f"⛔ Claude: {reason}")
    elif decision == "allow":
        allow()
    else:
        log_debug("Claude unsure, asking user")
        ask_user(f"🤔 Claude uncertain: {reason}" if reason else "🤔 Claude needs your decision")


def deny_or_ask_user(decision: str, reason: str, ask_message: str):
    """If Claude denies, deny. Otherwise always ask user (even if Claude allows)."""
    if decision == "deny":
        deny(f"⛔ Claude: {reason}")
    else:
        ask_user(ask_message)


# ============================================================================
# Main Logic
# ============================================================================

def main():
    log_debug("=" * 50)
    log_debug("Hook started")

    # 1. Read JSON input from stdin
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError:
        log_debug("ERROR: Cannot parse JSON input")
        ask_user("⚠️ Hook error: cannot parse input")
        return

    tool_name = request.get("tool_name", "")
    tool_input = request.get("tool_input", {})
    cwd = request.get("cwd", "")

    log_debug(f"Tool: {tool_name}")
    log_debug(f"Input: {json.dumps(tool_input, ensure_ascii=False)[:200]}")

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
    # PHASE 0: USER-INTERACTIVE TOOLS (skip all review, pass to user)
    # ========================================================================
    # These tools require direct user interaction (e.g. choosing options).
    # Auto-allowing them would bypass user input, so always pass through.
    USER_INTERACTIVE_TOOLS = ["AskUserQuestion", "ExitPlanMode"]
    if tool_name in USER_INTERACTIVE_TOOLS:
        log_debug(f"User-interactive tool {tool_name}, passing to user directly")
        ask_user(f"🔔 {tool_name} requires your attention")
        return

    # ========================================================================
    # PHASE 1: AUTO DENY (fast reject, no API call)
    # ========================================================================
    # Note: AUTO ALLOW is handled by settings.json rules before hook is called
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        danger = find_dangerous_pattern(command)
        if danger:
            reason = f"Dangerous pattern detected: {danger}"
            log_debug(f"Dangerous command detected: {reason}")
            deny(f"⛔ {reason}")
            return

    # ========================================================================
    # PATH CLASSIFICATION (collect paths, detect script, classify scope)
    # ========================================================================

    # Collect all relevant paths from the request
    paths_to_check = []
    if "file_path" in tool_input:
        paths_to_check.append(tool_input["file_path"])
    if "path" in tool_input:
        paths_to_check.append(tool_input["path"])

    # Detect script execution and read content (used by both Phase 2 and 3)
    script_content = ""
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        # Extract paths from Bash command
        path_matches = re.findall(r'(?:^|\s)([~/][^\s;|&<>]+)', command)
        paths_to_check.extend(path_matches)

        # Detect script execution pattern
        script_match = re.search(r'\b(python|python3|node|bash|sh)\s+([^\s;|&]+)', command)
        if script_match:
            script_path = script_match.group(2)
            log_debug(f"Detected script execution: {script_path}")
            script_full_path = os.path.expanduser(script_path)
            try:
                if not os.path.isabs(script_full_path):
                    script_full_path = os.path.join(cwd, script_full_path)
                if os.path.exists(script_full_path):
                    with open(script_full_path, "r") as f:
                        script_content = f.read()[:5000]
                    log_debug(f"Read script content: {len(script_content)} chars")
                    # Add script path to paths_to_check
                    if script_full_path not in paths_to_check:
                        paths_to_check.append(script_full_path)
                else:
                    log_debug(f"Script file not found: {script_full_path}")
            except Exception as e:
                log_debug(f"Could not read script: {e}")

    # Classify paths
    sensitive_path = next(
        (p for p in paths_to_check if is_sensitive_path(p)),
        "",
    )
    outside_path = next(
        (p for p in paths_to_check if not is_path_in_project(p, cwd, additional_dirs)),
        "",
    )

    log_debug(f"Path classification: sensitive={sensitive_path!r}, outside={outside_path!r}")

    # ========================================================================
    # PHASE 2: OUTSIDE PROJECT / SENSITIVE PATHS
    # (Opus reviews ALL content, but user ALWAYS has final say — Claude can only deny)
    # ========================================================================

    if sensitive_path or outside_path:
        flagged_path = sensitive_path or outside_path
        path_label = "Sensitive path" if sensitive_path else "Outside project"
        path_icon = "⚠️" if sensitive_path else "📁"
        log_debug(f"{path_label} detected: {flagged_path}")

        # Gather all content context for Opus review
        review_content = script_content  # Already read for script execution

        # For Write/Edit, include the code being written
        if tool_name in ("Write", "Edit") and not review_content:
            code = tool_input.get("content", "") or tool_input.get("new_string", "")
            if code:
                review_content = code[:5000]
                danger_patterns = has_code_danger_patterns(code)
                if danger_patterns:
                    log_debug(f"Dangerous code patterns in Write/Edit: {danger_patterns}")

        # Opus reviews with full content context
        decision, reason = review_request(request, review_content)
        log_debug(f"Opus decision: {decision}, reason: {reason}")

        # Always ask user for sensitive/outside paths — user has final say
        notify = f"{path_icon} {path_label}: {flagged_path}"
        if reason:
            opus_verdict = "⛔ DENIED" if decision == "deny" else "✅ OK" if decision == "allow" else "❓ Uncertain"
            notify += f"\n\nOpus ({opus_verdict}): {reason}"
        ask_user(notify)
        return

    # ========================================================================
    # PHASE 3: INSIDE PROJECT (Opus reviews, Claude can auto-approve)
    # ========================================================================

    # 3.1 Script execution with content inspection
    if script_content:
        log_debug("Script execution inside project, Opus reviewing content...")
        decision, reason = review_request(request, script_content)
        log_debug(f"Opus decision: {decision}, reason: {reason}")
        handle_claude_decision(decision, reason)
        return

    # 3.2 Write/Edit with dangerous code patterns
    # Writing code is NOT execution — project code may legitimately need
    # dangerous-looking patterns (cleanup scripts, template engines, etc.).
    # Opus can approve or escalate to user, but should never deny writing
    # project code.
    if tool_name in ("Write", "Edit"):
        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        danger_patterns = has_code_danger_patterns(content)
        if danger_patterns:
            log_debug(f"Dangerous code patterns in Write/Edit: {danger_patterns}")
            decision, reason = review_request(request)
            log_debug(f"Opus decision: {decision}, reason: {reason}")
            if decision == "deny":
                # Downgrade deny to ask — it's code, not execution
                log_debug("Downgrading deny to ask for code write")
                decision = "ask"
                reason = reason or "Code contains potentially dangerous patterns"
            handle_claude_decision(decision, reason)
            return

    # 3.3 Complex Bash commands
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        is_complex = (
            "&&" in command or
            "||" in command or
            "|" in command or
            ";" in command or
            len(command) > 100
        )
        if is_complex:
            log_debug("Complex Bash inside project, Opus reviewing...")
            decision, reason = review_request(request)
            log_debug(f"Opus decision: {decision}, reason: {reason}")
            handle_claude_decision(decision, reason)
            return

    # 3.4 WebFetch unknown domain (external network always needs user confirmation)
    if tool_name == "WebFetch":
        url = tool_input.get("url", "unknown")
        log_debug(f"WebFetch unknown domain: {url}")
        decision, reason = review_request(request)
        log_debug(f"Opus decision: {decision}, reason: {reason}")
        deny_or_ask_user(decision, reason,
                         f"🌐 Unknown domain: {url}\n\nOpus review: {reason or 'no issues found'}")
        return

    # 3.5 Default: Opus reviews all unmatched requests
    log_debug("No specific rule matched, Opus reviewing...")
    decision, reason = review_request(request)
    log_debug(f"Opus decision: {decision}, reason: {reason}")
    handle_claude_decision(decision, reason)


if __name__ == "__main__":
    main()
