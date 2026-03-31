# 🍯 Polyglot Deception Network & Log Analyzer

A production-grade, multi-language honeypot network featuring genuine polyglot architectures (Node.js & PHP), real backing databases (MySQL, PostgreSQL, Redis, Mongo), and legacy protocol traps (Insecure HTTPS/SSL). It captures attacker credentials, automated exploitations, toolkits, and C2 addresses while maintaining strict network isolation between the attacker-facing containers and the management core.

## 🔥 Advanced Architecture

Instead of merely simulating attacks in Python, the honeypot forces attackers to interact with **genuine, isolated vulnerable Docker containers** and official database engines, capturing highly sophisticated exploitation attempts natively.

```text
                      ATTACKER-FACING (honeypot_net)
┌──────────────────────────────────────────────────────────────────┐
│                   Honeypot Core (Python)                         │
│  SSH (10001) | HTTP (10002) | FTP (10003) | Telnet (10004)       │
│  SMTP (10005) | HTTPS (10443 - Legacy SSL Bait)                  │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│               Genuine Vulnerable Web Apps (Sandboxed)            │
│  [ vuln-node-rce  :8081 ]      [ vuln-node-ssrf :8082 ]          │
│  RCE via child_process         SSRF via Axios                    │
│  [ vuln-php-lfi   :8083 ]      [ vuln-php-sqli  :8084 ]          │
│  LFI via include()             SQLi via SQLite Concatenation     │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│               Genuine Database Engines                           │
│  [ MySQL 8: 3306 ]             [ PostgreSQL 15: 5432 ]           │
│  [ Redis 7: 6379 ]             [ MongoDB 6: 27017 ]              │
│  (Configured with highly verbose native logging)                 │
└──────────────────────────────────────────────────────────────────┘
                                 │
                   (Internal API Ingestion & Log Tailing)
                                 ▼
                         MANAGEMENT (mgmt_net)
┌──────────────────────────────────────────────────────────────────┐
│                Management API & Analytics Core                   │
│  DBLogParser ↔ SQLite ↔ FastAPI ↔ AI Orchestrator ↔ Dashboard    │
└──────────────────────────────────────────────────────────────────┘
```

## ✨ Polyglot Vulnerabilities & Sandboxing

All web applications are **real**, written natively, and execute payloads inside strictly isolated components. We emphasize **per-attacker sandboxing**:

| Microservice | Vulnerability | Exploitation Mechanism & Isolation |
| :--- | :--- | :--- |
| **Node.js RCE** | **Command Injection** | `child_process.exec()` allows injecting shell metacharacters. Payload is routed dynamically to a per-attacker `nsjail` root directory, blocking host escape entirely. |
| **Node.js SSRF** | **SSRF** | `axios.get(url)` requests internal cloud metadata. The container is completely cut off from the local `mgmt_net`, preventing lateral pivoting. |
| **PHP LFI** | **Path Traversal** | `include($_GET['page'])` naturally traverses the container filesystem, which is natively hardened via Docker's read-only semantics. |
| **PHP SQLi** | **SQL Injection** | `PDO` using dangerous string concatenation captures payload traversal logic via temporary SQLite memory schemas explicitly bound per user request. |

## 🤖 Future AI Integration

The `api/ai/orchestrator.py` module establishes our future roadmap for **LLM-driven honeypots**. In coming iterations, the sandbox behaviors, filesystem appearances, and internal data responses will be seamlessly manipulated in real-time by Language Models evaluating the incoming payloads dynamically.

## 🗄️ Database & Protocol Baits

- **Native Databases**: MySQL, PostgreSQL, Redis, and Mongo expose their native binary protocols to the internet natively. The Python `DBLogParser` background daemon endlessly tails their explicit audit logs to inject brute-forcing metrics straight into our dashboard.
- **Insecure SSL/TLS Bait**: The `HTTPS` listener automatically generates local certificates but aggressively downgrades its `sslContext` (disabling TLS 1.3/1.2, enforcing `SECLEVEL=0`) to serve as a magnet for legacy scanner bots hunting for POODLE/BEAST targets.
- **Python Core Traps**: The legacy Python systems continue to emulate TTY shells (Telnet, SSH) returning fake root hashes, capturing `wget/curl` malware drops, and maintaining open relay emulations for SMTP.

## 🛡️ Host Security & Ingestion

Every polyglot web container ships with an asynchronous logging mechanism. The millisecond an attacker payload hits their vulnerable endpoint, the script `HTTP POST`s the session details back to the secure, internal `mgmt_net`. 

1. **Network Segmentation**: Reaching the Management Dashboard requires navigating to localhost on the host machine. The vulnerable apps only possess internal routes to the ingestion API.
2. **API Keys**: All internal REST tracking relies on `X-API-Key` headers securely mapped via `.env`.
3. **Execution Containment**: The Node and PHP RCE vulnerabilities execute within strictly isolated scopes. Tools like `nsjail` ensure attacker sessions are purely ephemeral, read-only sinks.

## 📚 Documentation

Detailed documentation is available in the `docs/` directory:
- [Motivation & Philosophy](docs/motivation.md): Why this project was built and the design principles behind it.
- [Usage Guide](docs/usage.md): Step-by-step instructions for deployment, configuration, and monitoring.
- [Architecture Deep-Dive](docs/architecture.md): Detailed explanation of how the different components (Core, API, Vulnerabilities, DB) interact.
- [Future Enhancements](ENHANCEMENTS.md): The roadmap for upcoming features and research directions.

## 🚀 Quick Start

Ensure Docker and Make are installed, then provision everything simultaneously.

```bash
# Provide environment variables (ports, API keys)
cp .env.example .env

# Build and start the entire Polyglot network in the background
make run

# Monitor the logs natively with the integrated Terminal UI
python3 -m tui --api-key <YOUR_KEY>

# View the analytics dashboard
http://localhost:9090
```

## 📂 Project Structure

```text
.
├── analyzer/                 # CLI Log Analysis tool (Text regex parser)
├── api/                      # Main Python FastAPI Management App (SQLite, Websockets)
│   └── ai/                   # AI Orchestrator Module (LLM ingestion logic)
├── honeypot/                 # Core Asyncio TCP Server (SSH, HTTP, FTP, Telnet, SMTP, HTTPS)
├── tui/                      # Textual-based Terminal User Interface Client
├── vulnerabilities/          # Separated Polyglot Microservices
│   ├── vuln-node-rce/        # Node.js Command Injection Trap (nsjail sandbox)
│   ├── vuln-node-ssrf/       # Node.js SSRF Trap
│   ├── vuln-php-lfi/         # PHP Path Traversal Trap
│   └── vuln-php-sqli/        # PHP SQLi Trap (Ephemeral DB)
├── web/                      # React/Vite Frontend Web Dashboard
├── config.yaml               # Global Honeypot Settings & Protocol Flags
├── docker-compose.yml        # Multi-Container Orchestration definition
├── Dockerfile                # Honeypot Core NSJail build specification
├── Dockerfile.mgmt           # Management API & Nginx build specification
└── Makefile                  # Setup and teardown commands (`make run`, `make clean`)
```
