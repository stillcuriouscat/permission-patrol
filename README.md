# Permission Patrol

> AI-powered security guard for Claude Code permission requests

Permission Patrol uses a command hook with Claude CLI (Haiku) to intelligently review permission requests that aren't handled by deterministic rules. No separate API key required - uses your subscription quota.

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
         ├─ PHASE 1: Dangerous regex? ──→ Deny
         │
         ├─ PHASE 2: Script execution? ──→ Claude reviews script content
         │   (python xxx.py, pytest, node...)
         │
         └─ PHASE 3: Other cases ──→ Ask user
```

## Features

| Operation | Handling |
|-----------|----------|
| Delete files (`rm -rf`, `shred`) | ❌ Deny (settings.json) |
| Upload data (`curl POST`, `scp`) | ❌ Deny (settings.json) |
| GitHub delete (`gh repo delete`) | ❌ Deny (settings.json) |
| Read-only ops (`ls`, `cat`, `Read`) | ✅ Allow (settings.json) |
| Linters (`ruff`, `mypy`, `eslint`) | ✅ Allow (settings.json) |
| Trusted domains (`github.com`...) | ✅ Allow (settings.json) |
| GitHub CLI (`gh *`) | ✅ Allow (settings.json) |
| Run Python/pytest | 🤖 Claude reads script, checks for dangerous code |
| Write code with `os.remove` etc. | 🤖 Claude reviews |
| Unknown operations | 👤 Ask user |

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

## License

MIT
