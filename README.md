# CC Security Proxy

A security proxy that sits between your coding agent and untrusted third-party API relay stations. It inspects every response before forwarding to your agent, protecting against malicious script injection.

## Why

Third-party API relay stations (中转站) offer cheaper API access by reselling compute. But some inject malicious scripts into responses — for example, writing VBS files to your Windows Startup folder to serve ads. Your coding agent, which executes commands automatically, becomes a vector for these attacks.

CC Security Proxy adds a security layer between your agent and the relay, with three levels of protection.

## Modes

| Mode | Speed | Safety | How It Works |
|------|-------|--------|--------------|
| **default** | Instant | Minimal | Pass-through with logging. No blocking. |
| **protected** | ~2-5s | High | Static scan → Docker sandbox execution → behavioral analysis |
| **smart** | ~1-3s | Highest | Static pre-scan → LLM triage → sandbox (only if uncertain) |

### Default Mode
Forward everything, log suspicious patterns. Good for auditing — observe what your relay is sending before enabling blocking.

### Protected Mode
Extracts code blocks from the response, runs them in an isolated Docker container (no network, read-only filesystem, dropped capabilities), and watches for:
- Writes to persistence directories (Startup, LaunchAgents, crontab, systemd)
- Network connection attempts
- Shell config modification (.bashrc, .zshrc, .profile)
- Privilege escalation attempts
- Download-and-execute patterns

### Smart Mode
1. **Static pre-scan**: Catch obvious threats instantly (reverse shells, base64-encoded payloads)
2. **LLM triage**: Send response to a cheap LLM for classification (SAFE / SUSPICIOUS / MALICIOUS)
   - SAFE with high confidence → forward immediately
   - MALICIOUS with high confidence → block immediately
   - Uncertain → fall through to sandbox
3. **Sandbox fallback**: Only runs when the LLM isn't sure, minimizing latency

## Quick Start

### Prerequisites
- Python 3.11+
- Docker (for protected/smart modes)

### Install

```bash
git clone https://github.com/YOUR_USERNAME/cc-security-proxy.git
cd cc-security-proxy
pip install -e .
```

### Configure

```bash
cp .env.example .env
# Edit .env with your settings
```

Minimal `.env`:
```env
UPSTREAM_URL=https://your-relay.example.com
MODE=smart
LLM_API_KEY=sk-your-key-here
LLM_MODEL=gpt-4o-mini
```

### Run

```bash
# Smart mode (recommended)
cc-security-proxy --mode smart

# Protected mode (no LLM, sandbox-only)
cc-security-proxy --mode protected

# Default mode (observe only)
cc-security-proxy --mode default

# Custom port and upstream
cc-security-proxy --port 9090 --upstream https://other-relay.com
```

### Configure Your Agent

Set your coding agent's API base URL to the proxy:

```
API_BASE_URL=http://localhost:8080
```

For Claude Code, set the environment variable:
```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
```

## Architecture

```
Coding Agent ──POST /v1/chat/completions──▶ CC Security Proxy :8080
                                                  │
                                                  ├── Static scan (always)
                                                  │
                                                  ├── Mode decision:
                                                  │   ├── default: forward
                                                  │   ├── protected: Docker sandbox
                                                  │   └── smart: LLM → sandbox
                                                  │
                                                  ▼
                                          FORWARD or BLOCK
                                                  │
                                                  ▼
                                        Upstream Relay Station
```

## How It Detects Threats

### Static Scanner (all modes)
15+ regex patterns covering:
- Shell pipe injection (`curl | bash`, `wget | sh`)
- Base64 decode-and-execute
- Windows registry persistence
- macOS LaunchAgent creation
- crontab manipulation
- Reverse shells
- Hidden file writes (.bashrc, .profile)
- Privilege escalation (sudo, chmod +s)

### Sandbox (protected/smart modes)
- Docker container with `--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`
- 30-second execution timeout
- 128MB memory limit
- File diff inspection for persistence writes
- Process monitoring for suspicious commands

### LLM Auditor (smart mode)
- Configurable model (GPT-4o-mini, Claude Haiku, DeepSeek, Qwen — anything OpenAI-compatible)
- Security-focused system prompt
- 10-second timeout
- Falls back to sandbox on failure

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Proxy status, mode, upstream, stats |
| `GET /stats` | Request/block/error counts |
| `POST /v1/*` | API passthrough (all methods) |
| `* /*` | Catch-all passthrough |

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_HOST` | `127.0.0.1` | Listen address |
| `PROXY_PORT` | `8080` | Listen port |
| `UPSTREAM_URL` | (required) | Relay station URL |
| `MODE` | `smart` | `default` / `protected` / `smart` |
| `LLM_API_KEY` | — | API key for smart mode |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | LLM endpoint |
| `LLM_MODEL` | `gpt-4o-mini` | Model name |
| `LLM_TIMEOUT` | `10` | LLM request timeout (seconds) |
| `SANDBOX_TIMEOUT` | `30` | Sandbox execution timeout (seconds) |
| `SANDBOX_IMAGE` | `cc-security-sandbox` | Docker image name |
| `LOG_LEVEL` | `INFO` | Logging level |

## Limitations

- Sandbox requires Docker. On Windows, use Docker Desktop.
- LLM-based detection is not foolproof — obfuscated payloads may bypass it.
- The proxy adds latency (especially protected mode). Tune timeouts accordingly.
- Only inspects text content in API responses. Binary responses are passed through.
- Your agent must support custom API base URLs.

## License

MIT
