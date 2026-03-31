# Final Honeypot Architecture: Genuine Polyglot Network

I have completely transformed the honeypot into an advanced, distributed Polyglot deception network. We are no longer relying on basic python string-matching. Attackers will now hit **real Docker containers running genuine operating configurations and interpreters**.

## 1. Genuine Database Vectors (Dockerized)
Instead of simulating the protocol handshakes, the honeypot now forces attackers to interface directly with the actual underlying database engines.
- **MySQL 8 (`mysql:8`)**: Bound to a public-facing port, utilizing the `--general-log=1` flag to natively log all SQL payloads and login attempts.
- **PostgreSQL 15 (`postgres:15-alpine`)**: Configured with `logging_collector=on` to aggressively capture advanced enumerations natively.
- **Redis 7 (`redis:7-alpine`)**: Uses `--requirepass` to capture brute forces and `--loglevel verbose` to track commands.
- **MongoDB 6 (`mongo:6`)**: Leveraging the native profiler (`--profile 2`).
**Integration**: The Python FastAPI `mgmt` container runs a highly efficient `DBLogParser` background daemon (`api/db_parser.py`) utilizing `asyncio`. It acts like `tail -f` directly reading the raw JSON/syslog files produced by the DB containers in the shared Docker volume, immediately centralizing the attack data into the Dashboard SQLite format!

## 2. Polyglot Web Application Vectors
I have constructed **two completely independent Docker containers** running incredibly authentic and vulnerable application stacks:

### A. Node.js Honeypot (`honeypot-vuln-node`)
A fully-functional Express.js API designed to trap logic scanners.
- **Command Injection (RCE)**: Uses genuine `child_process.exec()`. If an attacker sends `; cat /etc/passwd`, it truly executes inside the isolated `alpine` sandbox!
- **Server-Side Request Forgery (SSRF)**: Employs `axios.get(req.query.url)`. Attackers hitting AWS metadata IPs (`169.254.169.254`) are logged instantly.
- **Eval/Code Injection**: Exposes a deadly `eval(req.body.formula)` endpoint, snaring attackers looking for Node.js object deserialization flaws.
- **CSTI / XSS / XS-Search**: Advanced frontend vulnerabilities served with deliberately disastrous Content-Security-Policy headers (`unsafe-inline`, `unsafe-eval`).

### B. PHP & Apache Honeypot (`honeypot-vuln-php`)
A classic LAMP setup tracking the most aggressive automated tools.
- **Path Traversal / Local File Inclusion (LFI)**: Employs a real `include($_GET['page'])`.
- **SQL Injection (SQLi)**: Connects to a volatile SQLite memory database using unsafe concatenated queries (`SELECT * FROM users WHERE username = '$user'`), perfectly simulating the real DB failure states when payload quotes are injected.
- **XML External Entity (XXE)**: Exposes a `POST` handler operating with `libxml_disable_entity_loader(false)` and `LIBXML_NOENT`, perfectly parsing malicious XML entity payloads in real time.
- **Remote Code Execution (RCE)**: A deadly `shell_exec($_GET['cmd'])` endpoint providing an unauthenticated shell to attackers within an isolated container.

*Note: I built a robust logging framework inside these apps. Right before a dangerous payload truly fires, they use `axios`/`curl` to rapidly `POST` the `session_id` and payload to our Python `mgmt` API's new `POST /api/internal/ingest/event` endpoint!*

## 3. Insecure HTTPS Protocol (Python Core)
Because you asked for an Insecure TLS trap, I added the `https` protocol to the central Python `HoneypotServer`.
- It executes `subprocess.run(["openssl"...])` locally if it doesn't already have certificates to self-sign dynamically.
- It intercepts the Python `ssl.SSLContext` and intentionally passes the `ssl.OP_NO_TLSv1_3` and `ssl.OP_NO_TLSv1_2` downgrade flags! 
- It lowers security levels (`ALL:@SECLEVEL=0`) to ensure vulnerability scanners (like `testssl.sh` or Nmap) definitively flag the port for legacy crypto vulnerabilities like SSLv3 POODLE and BEAST.

---

### How To Run The New Polyglot Lab
The network isolation prevents the attackers in the `vuln-php` and `vuln-node` containers from ever reaching your management dashboard. 

```bash
docker-compose down
make run
```
This automatically boots everything! Watch the traffic pour into `localhost:9090`!
