# Permission Patrol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Hook-blue)](https://docs.anthropic.com/en/docs/claude-code)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/)

> **AI-powered security guard for Claude Code permission requests**

A command hook that **reads script content before approving execution** — catches hidden `shutil.rmtree()` or `rm -rf` that prompt hooks can't see.

## The Problem

When Claude Code asks to run `python script.py`, a **prompt hook only sees the command string** — it can't read what's inside the script. So this gets approved:

```python
# script.py - looks innocent as a command
import shutil
shutil.rmtree("/home/user/important_data")  # 💀 Hidden danger
```

**Permission Patrol solves this** by using a **command hook** that actually reads the file content before deciding. No more blind approvals.

## Key Features

- 🔍 **Reads script content** — inspects Python, Node, pytest files before approval
- 🛡️ **Catches hidden dangers** — `shutil.rmtree()`, `os.remove()`, `rm -rf` buried in code
- ⚡ **Zero API cost for safe ops** — deterministic rules handle `git`, `ls`, linters
- 🤖 **AI review for ambiguous cases** — Claude Opus analyzes complex commands
- 🔔 **Desktop notifications** — know when Claude approved but needs your confirmation
- 📦 **No separate API key** — uses your Claude Code subscription quota

## How It Works

```
Request arrives
    │
    ├─ settings.json deny? ──→ Reject immediately (no API call)
    │   (rm -rf, curl POST, scp, gh repo delete...)
    │
    ├─ settings.json allow? ──→ Pass immediately (no API call)
    │   (git status, ls, Read, ruff, gh...)
    │
    └─ Neither? ──→ permission-guard.py hook
         │
         ├─ PHASE 0: User-interactive tool? ──→ Ask user (sound + notification)
         │   (ExitPlanMode, AskUserQuestion)
         │
         ├─ PHASE 1: Dangerous regex? ──→ Deny immediately
         │   (pipe to nc, encoded exfiltration...)
         │
         ├─ PATH CLASSIFICATION ──→ Collect paths, detect scripts, classify scope
         │   Sensitive path? Outside project? Script content?
         │
         ├─ PHASE 2: Outside project / Sensitive path?
         │   ──→ Opus reviews (with full content context)
         │   ──→ User ALWAYS has final say (Opus verdict shown in notification)
         │   Key principle: Opus can inform but NEVER auto-approve outside-project ops
         │
         └─ PHASE 3: Inside project
             │
             ├─ 3.1 Script execution? ──→ Opus reviews script content
             │   ├─ Opus deny ──→ Deny
             │   ├─ Opus allow ──→ Allow
             │   └─ Opus unsure ──→ Ask user
             │
             ├─ 3.2 Write/Edit with dangerous code patterns?
             │   ──→ Opus reviews (deny downgraded to ask — writing ≠ executing)
             │
             ├─ 3.3 Complex Bash (pipes, chains, long commands)?
             │   ──→ Opus reviews, can auto-approve or deny
             │
             ├─ 3.4 WebFetch unknown domain?
             │   ──→ Opus reviews (can deny, otherwise ask user)
             │
             └─ 3.5 Default ──→ Opus reviews, can auto-approve or deny
```

## Features

| Operation | Phase | Handling |
|-----------|-------|----------|
| ExitPlanMode, AskUserQuestion | Phase 0 | 🔔 Ask user (sound + notification) |
| Delete files (`rm -rf`, `shred`) | settings.json | ❌ Deny (no API call) |
| Upload data (`curl POST`, `scp`) | settings.json | ❌ Deny (no API call) |
| Pipe to nc (`\| nc host port`) | Phase 1 | ❌ Deny (regex, no API call) |
| GitHub delete (`gh repo delete`) | settings.json | ❌ Deny (no API call) |
| Read-only ops (`ls`, `cat`, `Read`) | settings.json | ✅ Allow (no API call) |
| Linters (`ruff`, `mypy`, `eslint`) | settings.json | ✅ Allow (no API call) |
| Trusted domains (`github.com`...) | settings.json | ✅ Allow (no API call) |
| GitHub CLI (`gh *`) | settings.json | ✅ Allow (no API call) |
| Sensitive paths (`/etc/`, `~/.ssh/`) | Phase 2 | 🤖 Opus reviews → user always decides |
| Outside project paths | Phase 2 | 🤖 Opus reviews → user always decides |
| Run script (in project) | Phase 3.1 | 🤖 Opus reviews content → auto allow/deny |
| Write/Edit dangerous code (in project) | Phase 3.2 | 🤖 Opus reviews → deny downgraded to ask |
| Complex Bash (in project) | Phase 3.3 | 🤖 Opus reviews → auto allow/deny |
| WebFetch unknown domain | Phase 3.4 | 🤖 Opus reviews → deny or ask user |
| Other unmatched requests | Phase 3.5 | 🤖 Opus reviews → auto allow/deny |

## Why Command Hook?

Claude Code supports two types of hooks for AI-powered review:

| | `type: "prompt"` | `type: "command"` (this project) |
|---|---|---|
| Cost | Uses subscription quota | Uses subscription quota (via CLI) |
| Setup | JSON config only | Python script |
| **Can read script files** | ❌ No | ✅ Yes |

**The key difference:** `prompt` hooks can only see the command string (e.g., `python3 script.py`). They cannot read what's inside `script.py`.

Permission Patrol uses a `command` hook that calls Claude CLI (Opus), so it can **read the actual script content** before deciding. This catches dangerous code like:

```python
# script.py looks innocent as a command, but contains:
import shutil
shutil.rmtree("/home/user/important_data")
```

A `prompt` hook would approve `python3 script.py` because the command looks safe. Permission Patrol reads the file and denies it.

## Requirements

- Claude Code with hooks support
- That's it! Uses Claude CLI internally (subscription quota)

## Installation

### 1. Merge permissions into settings.json

Add the `allow` and `deny` rules from `permissions.json` to your `~/.claude/settings.json`:

```json
{
  "permissions": {
    "allow": [
      "Bash(git *)",
      "Bash(gh *)",
      "WebFetch(domain:github.com)",
      ...
    ],
    "deny": [
      "Bash(rm -rf *)",
      "Bash(gh repo delete *)",
      ...
    ]
  }
}
```

### 2. Add hook to settings.json

```json
{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/permission-patrol/permission-guard.py",
            "timeout": 30000
          }
        ]
      }
    ]
  }
}
```

### 3. Restart Claude Code

## Files

| File | Description |
|------|-------------|
| `permission-guard.py` | Main hook script — 4-phase security review using Claude Opus |
| `permissions.json` | Reference allow/deny rules to merge into settings.json |
| `test_permission_guard.py` | 62 unit tests covering all phases and edge cases |

## How Opus Reviews Scripts

When you run `python3 script.py` or `pytest`:

1. Hook reads the script file content (up to 5000 chars)
2. Classifies paths: sensitive? outside project?
3. Sends content + request info to Claude CLI (Opus, using subscription quota)
4. Opus checks for:
   - File deletion (`shutil.rmtree`, `os.remove`)
   - Data upload (`requests.post`, socket connections)
   - Credential access (`~/.ssh`, `.env`)
   - Command injection patterns
5. Returns: `allow` / `deny` / `ask`

**Key principle:** For scripts outside the project or touching sensitive paths (Phase 2), Opus verdict is advisory — the user always makes the final decision. For scripts inside the project (Phase 3), Opus can auto-approve or auto-deny.

## Debug Logging

Logs are written to `~/.local/state/permission-patrol/permission-guard.log`:

```bash
tail -f ~/.local/state/permission-patrol/permission-guard.log
```

## Desktop Notifications (Linux)

On Linux, `ask_user()` triggers both:
- **Sound alert** via `paplay` (Ubuntu notification sound)
- **Desktop notification** via `notify-send` with context about the request

Examples of notification content:

```
🔔 ExitPlanMode requires your attention
```

```
📁 Outside project: /etc/hostname

Opus (✅ OK): Reading hostname is a safe read-only operation
```

```
⚠️ Sensitive path: ~/.ssh/config

Opus (⛔ DENIED): Writing to SSH config could compromise security
```

The Opus verdict is shown for reference, but the user always makes the final decision for Phase 2 requests. `deny()` does NOT trigger sound or notification — there's nothing for the user to act on.

## Customization

All permission rules live in `~/.claude/settings.json`. The `permissions.json` in this repo is just a reference template.

To customize, edit your `~/.claude/settings.json` directly:

```json
{
  "permissions": {
    "allow": [
      "WebFetch(domain:your-trusted-site.com)",
      "Bash(your-safe-command *)"
    ],
    "deny": [
      "Bash(your-dangerous-command *)"
    ]
  }
}
```

## Use Cases

- **AI agent security** — prevent autonomous code execution from deleting files or exfiltrating data
- **Claude Code hardening** — add an extra layer of review for permission requests
- **Script inspection** — automatically review Python/Node scripts before execution
- **Sensitive path protection** — require confirmation for operations on `~/.ssh`, `/etc/`, `.env`

## See Also

- [Claude Code Hooks Documentation](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [Boris Cherny's Claude Code Tips](https://x.com/bcherny) — tip 8c inspired this project

## License

MIT

---

**Keywords:** claude code, claude code hook, permission hook, ai agent security, command hook, prompt hook, script inspection, claude code security, anthropic, ai safety
