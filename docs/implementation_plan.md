# Implementation Plan: Genuine Vulnerable Systems & Polyglot Addition

I completely understand now. Python reconstructions are too limited for advanced attackers. Instead, we will integrate **REAL, official systems** running in isolated Docker containers. This will be an **addition** to our existing Python honeypot network, so we don't lose the existing SSH/FTP/SMTP monitors.

## 1. Real DBMS Honeypots
We will spin up actual, official docker images for popular databases with deliberately weak configurations. Because they are the real systems, no attacker exploit will fail due to "simulated" logic.
- **MySQL (`mysql:8.0`)**: Bound to port 3306. Configured with `general_log=1` to log every single connection, login attempt, and SQL query to a shared volume.
- **PostgreSQL (`postgres:15`)**: Bound to port 5432. Configured with strict logging (`log_connections = on`, `log_statement = 'all'`) so we capture all payloads.
- **Redis (`redis:7`)**: Bound to port 6379. Configured with a weak `requirepass`, logging all authentication attempts and executed commands.
- **MongoDB (`mongo:6`)**: Bound to port 27017. Configured with high-verbosity profiling.
**Dashboard Integration**: We will build a Background Task in the Python Management API that continuously tails and parses these native database log files from a shared Docker volume, translating real DB events into our `connections` and `credentials` SQLite tables for the dashboard.

## 2. Real Web Vulnerability Containers (Polyglot)
Instead of simulating things in Python, we will build dedicated, intentionally vulnerable applications using the actual languages you requested.

### A. PHP/Apache Container (`vuln-php`)
- **Real File Inclusion / Path Traversal (LFI)**: A real PHP script using `include($_GET['page'])`. If they hit `../../../../etc/passwd`, it really returns the container's passwd file!
- **Real SQL Injection (SQLi)**: A real vulnerable PDO query.

### B. Node.js Container (`vuln-node`)
- **Real Command Injection (RCE)**: Uses Node.js `child_process.exec()` unsafely. If they send `| ls -la`, the container executes it safely within its isolated Sandbox and returns the output.
- **Advanced XSS & CSP Bypass**: Real vulnerable Express.js views with no output encoding and `unsafe-inline` Content-Security-Policy headers.
- **CSTI & XS-Search**: Real endpoints configured to be vulnerable to template injection and Cross-Site Search side-channel timing attacks.
**Dashboard Integration**: Since we are writing these web apps, we will add a 3-line logging function at the top of each vulnerable route. Before the attack executes, the app will make a secure HTTP `POST` to the Management API's internal IP to log the attacker's details.

## 3. Insecure HTTPS (Python Core Addition)
We will add an `https` protocol to our existing Python core. It will wrap the asyncio server socket in an `ssl` context strictly configured to **reject modern TLS** and deliberately negotiate vulnerable **TLSv1/SSLv3** protocols with weak ciphers. This creates a honeypot for legacy cryptographic scanners checking for POODLE/BEAST.

---

## User Review Required

By orchestrating **Real MySQL, Real Postgres, Real Redis**, and **Real vulnerable PHP/Node.js apps** via Docker Compose, we achieve 100% authenticity. 

Does this approach perfectly match your requirement to use real, raw systems for these additions?
