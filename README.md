# 🚔 Permission Patrol

> AI-powered security guard for Claude Code permission requests

Permission Patrol is a Claude Code hook that uses **Opus 4.5** to intelligently review permission requests, automatically approving safe operations and blocking dangerous ones.

## Features

| Operation | Handling |
|-----------|----------|
| Delete files (`rm`, `unlink`) | ❌ Auto-deny |
| Upload data (`curl POST`, `scp` to remote) | ❌ Auto-deny |
| Access trusted domains | ✅ Auto-approve |
| Access unknown domains | ⏸️ Ask user (auto-add to whitelist after approval) |
| Access paths outside project | ⏸️ Ask user |
| Run code with dangerous patterns | 🤖 Opus 4.5 reviews |

## How It Works

```
┌─────────────────────────────────────────────┐
│           Claude Code Request               │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│          permission-guard.py                │
├─────────────────────────────────────────────┤
│  1. Quick pattern check (regex)             │
│  2. Trusted domain whitelist                │
│  3. Project path validation                 │
│  4. Opus 4.5 deep analysis                  │
└──────────────────┬──────────────────────────┘
                   ↓
           allow / deny / ask
```

### Self-Learning Domain Whitelist

When you approve a WebFetch request for a new domain, it's automatically added to the whitelist. Next time, any page on that domain will be auto-approved.

```
First visit to example.com
    → Ask user for permission
    → User approves
    → Domain added to trusted-domains.txt

Second visit to example.com/any-page
    → Auto-approved ✅
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/permission-patrol.git
cd permission-patrol
```

### 2. Install dependencies

```bash
pip install anthropic
```

### 3. Set up your API key

```bash
export ANTHROPIC_API_KEY="your-api-key"
```

### 4. Configure Claude Code hooks

Add the following to your `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PermissionRequest": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/permission-patrol/permission-guard.py",
            "timeout": 120
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/permission-patrol/auto-whitelist-domain.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

### 5. Restart Claude Code

Hooks are loaded at startup, so you need to restart Claude Code for changes to take effect.

## Files

| File | Description |
|------|-------------|
| `permission-guard.py` | Main PermissionRequest hook - reviews all permission requests |
| `auto-whitelist-domain.py` | PostToolUse hook - auto-adds approved domains to whitelist |
| `trusted-domains.txt` | Domain whitelist (grows automatically) |

## Configuration

### Trusted Domains

Edit `trusted-domains.txt` to add/remove trusted domains:

```
# Code hosting
github.com
gitlab.com

# Package registries
pypi.org
npmjs.com

# Your custom domains
your-internal-site.com
```

### Security Rules

The following patterns are **always denied** (in `permission-guard.py`):

- `rm` commands targeting `/`, `~`, or `/home`
- `curl` with POST/upload flags
- `scp`/`rsync` to remote hosts
- `mkfs`, `dd` to disk devices
- Reverse shell patterns (`nc -e`, `bash -i`, `/dev/tcp`)

## Testing

```bash
# Test dangerous command detection (should be denied)
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/home/user"}' | python3 permission-guard.py

# Test trusted domain (should be allowed)
echo '{"tool_name":"WebFetch","tool_input":{"url":"https://github.com/test"},"cwd":"/home/user"}' | python3 permission-guard.py

# Test unknown domain (should ask user - no output)
echo '{"tool_name":"WebFetch","tool_input":{"url":"https://unknown.com"},"cwd":"/home/user"}' | python3 permission-guard.py
```

## Debugging

```bash
# Run Claude Code with debug output
claude --debug
```

## Requirements

- Python 3.8+
- `anthropic` Python SDK
- Claude Code with hooks support
- Anthropic API key (for Opus 4.5 reviews)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
