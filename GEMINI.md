# 🍯 Polyglot Deception Network & Log Analyzer - Project Context & Harness

## Project Overview
This project is a production-grade, multi-language honeypot network featuring genuine polyglot architectures (Node.js & PHP), real backing databases (MySQL, PostgreSQL, Redis, Mongo), and legacy protocol traps (Insecure HTTPS/SSL). It captures attacker credentials, automated exploitations, toolkits, and C2 addresses while maintaining strict network isolation between the attacker-facing containers and the management core.

## 🏗️ Architecture & Infrastructure
- **Honeypot Core (Python):** Asynchronous TCP Server (`src/backend/core/`) listening on multiple ports:
  - SSH (10001)
  - HTTP (10002) - Acting as an "Enterprise User Portal" bait (Synergy Corp).
  - FTP (10003)
  - Telnet (10004) - Ubuntu login bait.
  - SMTP (10005)
  - HTTPS (10443) - Legacy SSL Bait.
- **Genuine Vulnerable Web Apps (Traps):**
  - Node.js RCE (`traps/node-rce` :8081) - Command Injection via `child_process`.
  - Node.js SSRF (`traps/node-ssrf` :8082) - SSRF via Axios.
  - PHP LFI (`traps/php-lfi` :8083) - Path Traversal.
  - PHP SQLi (`traps/php-sqli` :8084) - SQLite Injection.
- **Genuine Database Engines:** MySQL (3307), PostgreSQL (5433), Redis (6380), MongoDB (27018) configured with highly verbose logging for analysis.
- **Management API & Analytics Core:** FastAPI backend (`src/backend/api/`) + React Frontend (`src/frontend/`) served on `localhost:9090`. Uses SQLite and Textual UI (`src/backend/cli/`).

## 📂 Current Directory Structure
*DO NOT revert to the old structure (e.g., `vulnerabilities/`, `honeypot/`, `api/`, `web/`). The project was explicitly migrated to a solid, unified structure as follows:*
```text
.
├── config.yaml               # Global Honeypot Settings & Protocol Flags
├── docker-compose.yml        # Multi-Container Orchestration definition
├── docs/                     # Detailed technical documentation
├── infrastructure/           # Dockerfiles and server configs (planned/in progress)
├── src/                      # Source code (backend core, API, CLI tools, frontend)
│   ├── backend/
│   │   ├── api/              # FastAPI Management App
│   │   ├── cli/              # Log Analysis & TUI
│   │   └── core/             # Asyncio TCP Server (SSH, HTTP, FTP, Telnet, SMTP)
│   └── frontend/             # React/Vite Frontend Web Dashboard
├── traps/                    # Separated Polyglot Microservices (Node.js & PHP traps)
└── manage.sh                 # Management script
```

## 🔄 Current Status & Recent Changes (Do Not Compact)
- **Directory Restructuring Completed:** Migrated old root folders to `src/backend/`, `src/frontend/`, and `traps/`. `docker-compose.yml` and Dockerfiles were updated to correctly resolve context paths.
- **Frontend Update:** React dashboard title and UI updated to "SysAdmin Dashboard" and "SysAdmin Management Console" to make the management side look like a realistic admin utility.
- **Config Update:** Increased rate limit `max_connections` to 500 in `config.yaml`. Changed telnet hostname to `ubuntu-server`.
- **HTTP Honeypot Bait (Synergy Corp):** `src/backend/core/protocols/http.py` was heavily modified to serve a highly realistic "Synergy Corp - Enterprise Portal" instead of a default Apache page.
  - Includes a fake `/login` endpoint that redirects to a `/dashboard` showing links to our other vulnerabilities (`traps/`).
- **Active Bug - HTTP Honeypot Connection Drop:**
  - **Issue:** `curl http://localhost:10002` currently returns `curl: (52) Empty reply from server`.
  - **Root Cause:** A recent modification to the `_safe_read` loop in `http.py`'s `handle` method (attempting to properly parse HTTP headers by waiting for `\r\n\r\n`) is failing. The connection drops or blocks before sending the HTTP response.
  - **Next Step Required:** Debug and fix the `asyncio` stream reading loop in `src/backend/core/protocols/http.py` (around line 523, `def handle`). The request needs to be properly read (headers and optional body) and then properly passed to `self._parse_request` and the corresponding response handler (e.g., `self._handle_get`), ensuring `self._safe_write(writer, response)` is actually executed.
- **Documentation Migration:** Moved old markdown files (`ENHANCEMENTS.md`, etc.) to the `docs/` folder to keep the root directory clean.

## 🛠️ Engineering Harness & Guidelines
1. **Preserve Context Uncompacted:** Whenever updating `GEMINI.md` or other context-heavy documents, **do not compress or abbreviate the history and technical specifics.** Future LLM interactions rely heavily on these granular details to avoid repeating mistakes (such as the HTTP 52 error or reverting folder paths).
2. **Solid Architecture Focus:** Maintain the established directory tree. Do not move `Dockerfile` and `docker-compose.yml` out of the root folder, as this disrupts the Docker build context.
3. **Realistic Deception:** When adding "bait" or updating honeypot logic, prioritize high realism (e.g., the Synergy Corp portal). Avoid default or obvious "honeypot" strings unless intended to be discovered by specific scanners.
4. **Validation & Testing:** Always verify changes by hitting the actual endpoint (`curl -I http://localhost:10002` or `nc localhost 10001`) and checking `docker logs hp3-honeypot-1`. Do not assume a code change works just because syntax is valid.
5. **No Blind Fallbacks:** If a bug occurs (like the current HTTP empty reply), investigate the specific Python logic handling the raw byte streams instead of reverting the entire file.

---
*End of Context Harness*