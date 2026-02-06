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
- 🤖 **AI review for ambiguous cases** — Claude Haiku analyzes complex commands
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
         ├─ PHASE 1: Dangerous regex? ──→ Deny immediately
         │   (pipe to nc, encoded exfiltration...)
         │
         ├─ PHASE 2: Script execution? ──→ Claude reviews script content
         │   (python xxx.py, pytest, node...)
         │   ├─ Claude deny ──→ Deny
         │   ├─ Claude allow + in project ──→ Allow
         │   └─ Claude allow + outside project ──→ Ask user (double confirm)
         │
         └─ PHASE 3: Other cases ──→ Claude reviews first
             ├─ Claude deny ──→ Deny
             ├─ Claude allow + in project ──→ Allow
             ├─ Claude allow + sensitive path ──→ Ask user (double confirm)
             └─ Claude allow + outside project ──→ Ask user (double confirm)
```

## Features

| Operation | Handling |
|-----------|----------|
| Delete files (`rm -rf`, `shred`) | ❌ Deny (settings.json) |
| Upload data (`curl POST`, `scp`) | ❌ Deny (settings.json) |
| Pipe to nc (`\| nc host port`) | ❌ Deny (regex) |
| GitHub delete (`gh repo delete`) | ❌ Deny (settings.json) |
| Read-only ops (`ls`, `cat`, `Read`) | ✅ Allow (settings.json) |
| Linters (`ruff`, `mypy`, `eslint`) | ✅ Allow (settings.json) |
| Trusted domains (`github.com`...) | ✅ Allow (settings.json) |
| GitHub CLI (`gh *`) | ✅ Allow (settings.json) |
| Run Python/pytest (in project) | 🤖 Claude reviews → auto allow/deny |
| Run script (outside project) | 🤖 Claude reviews → user confirms |
| Sensitive paths (`/etc/`, `~/.ssh/`) | 🤖 Claude reviews → user confirms |
| Complex Bash commands | 🤖 Claude reviews → auto or user confirms |

## Why Command Hook?

Claude Code supports two types of hooks for AI-powered review:

| | `type: "prompt"` | `type: "command"` (this project) |
|---|---|---|
| Cost | Uses subscription quota | Uses subscription quota (via CLI) |
| Setup | JSON config only | Python script |
| **Can read script files** | ❌ No | ✅ Yes |

**The key difference:** `prompt` hooks can only see the command string (e.g., `python3 script.py`). They cannot read what's inside `script.py`.

Permission Patrol uses a `command` hook that calls Claude CLI, so it can **read the actual script content** before deciding. This catches dangerous code like:

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
| `permission-guard.py` | Main hook script - calls Claude CLI for intelligent review |
| `permissions.json` | Reference allow/deny rules to merge into settings.json |

## How Claude Reviews Scripts

When you run `python3 script.py` or `pytest`:

1. Hook reads the script file content
2. Sends content + request info to Claude CLI (Haiku)
3. Claude checks for:
   - File deletion (`shutil.rmtree`, `os.remove`)
   - Data upload (`requests.post`, socket connections)
   - Credential access (`~/.ssh`, `.env`)
   - Command injection patterns
4. Returns: `allow` / `deny` / `ask`

## Debug Logging

Logs are written to `/tmp/permission-guard.log`:

```bash
tail -f /tmp/permission-guard.log
```

## Desktop Notifications (Linux)

On Linux, when Claude approves but user confirmation is still needed (outside project / sensitive path), a desktop notification is sent via `notify-send`:

```
✅ Claude approved, but path outside project:
/etc/hostname

Please confirm.
```

This helps you know Claude has already reviewed the request before you see the confirmation dialog.

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
