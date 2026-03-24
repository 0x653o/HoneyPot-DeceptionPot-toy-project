# 🍯 Honeypot & Log Analyzer

---

# My first toy project with Antigravity(Claude opus 4.6 thinking/Planning)

---

A production-grade, multi-protocol honeypot with per-connection sandboxing, deliberate bait vulnerabilities, real-time analytics, and a management dashboard. Captures attacker credentials, commands, toolkits, and C2 addresses while keeping the host server fully isolated.

## Architecture

```
                      ATTACKER-FACING (honeypot_net)
┌─────────────────────────────────────────────────────┐
│                Docker: Honeypot Core                 │
│             asyncio + nsjail per-connection           │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐        │
│  │  SSH   │ │  HTTP  │ │  FTP   │ │ Telnet │        │
│  │ :10001 │ │ :10002 │ │ :10003 │ │ :10004 │        │
│  └────────┘ └────────┘ └────────┘ └────────┘        │
│  ┌────────┐                                          │
│  │  SMTP  │  → data/honeypot.log  (text, regex)     │
│  │ :10005 │  → data/honeypot.db   (SQLite, API)     │
│  └────────┘                                          │
└─────────────────────────────────────────────────────┘
                             │ shared volume (read-only)
                      MANAGEMENT (mgmt_net)
┌─────────────────────────────────────────────────────┐
│              Docker: Management Server               │
│  Nginx (:9090) → FastAPI (:8000) → React Dashboard  │
│  TUI binary connects via API                         │
└─────────────────────────────────────────────────────┘
```

## Features

### Honeypot Core

- **5 protocols**: SSH, HTTP, FTP, Telnet, SMTP — all with realistic banners and response flows
- **Per-connection sandboxing**: nsjail with PID/mount/network/user namespace isolation
- **Credential capture**: username/password harvesting across all protocols
- **C2 detection**: captures download URLs from `wget`/`curl` in Telnet fake shell
- **Dual logging**: text file (analyzer regex-compatible) + SQLite (API queryable)
- **Rate limiting**: sliding window per-IP with whitelist/blacklist support

### Bait Vulnerabilities

Deliberate, realistic-looking vulnerabilities designed to attract and engage attackers. **All baits are pure string I/O** — no real execution, no sandbox escape risk.

| Protocol   | Baits                                                    | Purpose                              |
| ---------- | -------------------------------------------------------- | ------------------------------------ |
| **HTTP**   | `/.env` (Laravel env with fake AWS keys, DB creds)       | Attracts info-leak scanners          |
|            | `/wp-login.php` (real-looking WordPress form)            | Captures POST credentials            |
|            | `/phpinfo.php` (PHP 8.1.27, `disable_functions` empty)   | Shows "exploitable" PHP config       |
|            | `/admin/` (401 + `WWW-Authenticate: Basic`)              | Traps Basic auth credential sprayers |
|            | `/.git/config` (fake GitHub remote URL)                  | Attracts `.git` directory scanners   |
|            | `/wp-config.php.bak` (WordPress DB credentials)          | Config backup hunters                |
|            | `/server-status` (Apache status with stats)              | Server info leak                     |
| **FTP**    | `backup.sql` / `credentials.txt` in directory listing    | Sensitive file bait                  |
|            | `RETR backup.sql` → fake MySQL dump with bcrypt hashes   | Credential harvesting bait           |
|            | `STOR` in `/upload/` → fake `226 Transfer complete`      | Captures uploaded payloads           |
| **SSH**    | Banner: `SSH-2.0-OpenSSH_7.4` (CVE-2018-15473)           | Attracts automated scanners          |
| **Telnet** | `cat /etc/shadow` → fake `$6$` password hashes           | Looks like root access obtained      |
|            | `sudo` → asks password, logs it, switches to root prompt | Privilege escalation bait            |
|            | `wget`/`curl` → simulates successful download            | Captures C2 URLs & payloads          |
| **SMTP**   | `VRFY` confirms any username exists (`250`)              | Email harvester bait                 |
|            | `RCPT TO` accepts any external domain (open relay)       | Spammer bait                         |

> **Security guarantee**: Every bait response is a hardcoded Python string template. No `subprocess`, no `exec`, no filesystem writes, no outbound network calls. The nsjail + Docker + seccomp layers remain untouched.

### Host Security

- Docker network isolation (honeypot vs management on separate networks)
- nsjail per-connection (PID/mount/network/user namespaces, seccomp, `no-new-privileges`)
- Custom seccomp syscall whitelist (~95 safe syscalls)
- Read-only root filesystem (`read_only: true`)
- `cap_drop: ALL` with minimal `cap_add`
- Non-root container user
- Management API bound to `127.0.0.1` only (never exposed to attackers)

### Analytics

- Real-time web dashboard with WebSocket live connection feed
- IP geolocation (MaxMind GeoLite2)
- Reverse DNS lookups
- Bait trigger tracking (`bait_triggered` events in database)
- CLI log analyzer with text/JSON reports
- TUI binary for terminal-based monitoring

## Quick Start

### Docker (Recommended)

```bash
# Clone and start
git clone <repo-url>
cd Honey&LogWithAnalyze
docker compose up -d

# View dashboard
open http://localhost:9090
```

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Start honeypot
python -m honeypot --config config.yaml

# Start API server (separate terminal)
uvicorn api.main:app --host 127.0.0.1 --port 9090
```

### Run Analyzer

```bash
# Text report from database
python -m analyzer --db data/honeypot.db

# Text report from log file
python -m analyzer --log data/honeypot.log

# JSON output with GeoIP enrichment
python -m analyzer --db data/honeypot.db --json --geoip data/GeoLite2-City.mmdb

# Filter by protocol
python -m analyzer --db data/honeypot.db --protocol ssh --top 50
```

### TUI Monitor

```bash
# Run TUI dashboard
python -m tui --api http://localhost:9090
```

## Testing Connections

```bash
# SSH — will show OpenSSH_7.4 banner
nc localhost 10001

# HTTP — try bait routes
curl http://localhost:10002/.env
curl http://localhost:10002/wp-login.php
curl http://localhost:10002/phpinfo.php
curl -u admin:password http://localhost:10002/admin/

# FTP — browse sensitive files
ftp localhost 10003

# Telnet — interactive fake shell
telnet localhost 10004

# SMTP — test open relay
telnet localhost 10005
```

## GeoIP Setup (Optional)

1. Sign up at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
2. Download **GeoLite2-City** database
3. Place `GeoLite2-City.mmdb` in `data/`

## Configuration

Edit `config.yaml` to customize:

- Protocol ports and banners
- Sandbox time/memory limits
- Rate limiting thresholds
- Management API bind address
- Domain settings (future feature)

## Project Structure

```
├── honeypot/              # Honeypot server (asyncio + nsjail)
│   ├── __main__.py        # CLI: python -m honeypot
│   ├── core.py            # Main async server loop
│   ├── config.py          # Typed config loader (dataclasses)
│   ├── sandbox.py         # nsjail wrapper
│   ├── logger.py          # Dual-sink logger (file + SQLite)
│   ├── utils.py           # Rate limiter, session IDs
│   └── protocols/         # Protocol handlers
│       ├── base.py        # BaseProtocolHandler ABC
│       ├── ssh.py         # SSH (CVE-2018-15473 bait banner)
│       ├── http.py        # HTTP (7 bait routes)
│       ├── ftp.py         # FTP (sensitive files, writable upload)
│       ├── telnet.py      # Telnet (shadow, sudo, download sim)
│       └── smtp.py        # SMTP (VRFY confirm, open relay)
├── analyzer/              # Log analysis library
│   ├── __main__.py        # CLI: python -m analyzer
│   ├── parser.py          # Text + SQLite parser
│   ├── enrichment.py      # GeoIP + reverse DNS
│   └── report.py          # Text + JSON reports
├── api/                   # FastAPI management API
│   ├── main.py            # App + static mount guard
│   ├── database.py        # Read-only SQLite queries
│   ├── models.py          # Pydantic schemas
│   └── routes/            # Dashboard, logs, analysis endpoints
├── web/                   # React dashboard (Vite)
│   └── src/
│       ├── api.js         # API client + WebSocket (auto wss:/ws:)
│       ├── index.css      # Glassmorphism design system
│       └── pages/         # Dashboard, Attackers, Logs
├── tui/                   # Terminal UI (Textual)
│   ├── __main__.py        # CLI: python -m tui
│   ├── app.py             # Tabbed TUI with auto-refresh
│   └── build.spec         # PyInstaller spec
├── config.yaml            # Honeypot configuration
├── nginx.conf             # Nginx reverse proxy config
├── supervisord.conf       # Process manager config
├── docker-compose.yml     # Container orchestration
├── Dockerfile             # Honeypot container
├── Dockerfile.mgmt        # Management container (multi-stage)
├── seccomp-profile.json   # Custom syscall whitelist
├── .dockerignore          # Build exclusions
└── requirements.txt       # Python dependencies
```

## License

MIT
