# Permission Patrol

> AI-powered security guard for Claude Code permission requests

Permission Patrol uses a command hook with Opus API to intelligently review permission requests that aren't handled by deterministic rules.

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
         ├─ PHASE 2: Script execution? ──→ Opus reviews script content
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
| Run Python/pytest | 🤖 Opus reads script, checks for dangerous code |
| Write code with `os.remove` etc. | 🤖 Opus reviews |
| Unknown operations | 👤 Ask user |

## Why API Key?

Claude Code supports two types of hooks for AI-powered review:

| | `type: "prompt"` | `type: "command"` (this project) |
|---|---|---|
| Cost | Uses subscription quota | Requires separate API key |
| Setup | JSON config only | Python script |
| **Can read script files** | ❌ No | ✅ Yes |

**The key difference:** `prompt` hooks can only see the command string (e.g., `python3 script.py`). They cannot read what's inside `script.py`.

Permission Patrol uses a `command` hook so Opus can **read the actual script content** before deciding. This catches dangerous code like:

```python
# script.py looks innocent as a command, but contains:
import shutil
shutil.rmtree("/home/user/important_data")
```

A `prompt` hook would approve `python3 script.py` because the command looks safe. Permission Patrol reads the file and denies it.

**Trade-off:** You pay for API calls, but get deeper security inspection.

## Requirements

- Claude Code with hooks support
- Anthropic API key (stored in `~/.claude/anthropic-api-key`)
- `anthropic` Python SDK (`pip install anthropic`)

## Installation

### 1. Set up API key

```bash
# Create API key file (chmod 600 for security)
echo "sk-ant-xxxxx" > ~/.claude/anthropic-api-key
chmod 600 ~/.claude/anthropic-api-key
```

### 2. Merge permissions into settings.json

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

### 3. Add hook to settings.json

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

### 4. Restart Claude Code

## Files

| File | Description |
|------|-------------|
| `permission-guard.py` | Main hook script - calls Opus API for intelligent review |
| `permissions.json` | Reference allow/deny rules to merge into settings.json |

## How Opus Reviews Scripts

When you run `python3 script.py` or `pytest`:

1. Hook reads the script file content
2. Sends content + request info to Opus
3. Opus checks for:
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
