# Permission Patrol

> AI-powered security guard for Claude Code permission requests

Permission Patrol combines Claude Code's built-in permissions with an Opus agent hook for intelligent security review. **No API key required** - uses your Claude Code subscription.

## How It Works

```
Request arrives
    │
    ├─ In permissions.deny? ──→ Reject immediately (no quota used)
    │   (rm -rf, curl POST, scp...)
    │
    ├─ In permissions.allow? ──→ Pass immediately (no quota used)
    │   (git status, ls, Read, ruff...)
    │
    └─ Neither? ──→ Opus agent reviews
         │
         ├─ If running a script ──→ Read script content, check for dangerous code
         │
         └─ Make decision: allow / deny / ask
```

## Features

| Operation | Handling |
|-----------|----------|
| Delete files (`rm -rf`, `shred`) | ❌ Reject |
| Upload data (`curl POST`, `scp`) | ❌ Reject |
| Read-only ops (`ls`, `cat`, `Read`) | ✅ Pass |
| Linters (`ruff`, `mypy`, `eslint`) | ✅ Pass |
| Trusted domains (`github.com`, `pypi.org`) | ✅ Pass |
| git push | ⏸️ Opus reviews → Ask user |
| Run Python/pytest | 🤖 Opus reads script, checks for dangerous code |
| Unknown operations | 🤖 Opus decides |

## Installation

### 1. Merge permissions.json into settings.json

Merge the `deny` and `allow` rules from `permissions.json` into your `~/.claude/settings.json`:

```bash
cat permissions.json
```

### 2. Merge hooks.json into settings.json

Merge the hooks configuration from `hooks.json` into `~/.claude/settings.json`.

### 3. Final settings.json Structure

```json
{
  "permissions": {
    "deny": [
      "Bash(rm -rf *)",
      ...
    ],
    "allow": [
      "Read(*)",
      "Bash(git status *)",
      ...
    ]
  },
  "hooks": {
    "PermissionRequest": [
      {
        "hooks": [
          {
            "type": "agent",
            "model": "opus",
            ...
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
| `permissions.json` | Deterministic rules (direct allow/deny, no quota used) |
| `hooks.json` | Opus agent hook (intelligent review, uses subscription quota) |

## Opus Agent Capabilities

When a request reaches the agent, it will:

1. **Analyze the request** - Understand what operation is being performed
2. **Inspect script content** - If running `python xxx.py` or `pytest`, use Read tool to check:
   - File deletion operations
   - HTTP upload/data exfiltration
   - Command injection risks
   - Credential/key access
   - Network connections
3. **Make a decision** - allow / deny / ask

## Customization

### Add Trusted Domains

Edit `permissions.json`, add to `allow`:

```json
"WebFetch(url: https://your-trusted-domain.com/*)"
```

### Add Dangerous Commands

Edit `permissions.json`, add to `deny`:

```json
"Bash(your-dangerous-command *)"
```

### Adjust Agent Behavior

Edit the prompt in `hooks.json` to modify review rules.

## Requirements

- Claude Code with hooks support
- Claude Code subscription (Pro/Max)

## License

MIT
