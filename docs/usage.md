# 🛠️ Getting Started & Usage Guide

This guide covers everything from deployment to advanced configuration for the Honeypot System.

---

## 🚀 Deployment (Docker Compose)

The easiest way to get the entire system running is through `docker-compose`.

### 1. Configure Your Environment
Create a `.env` file based on `.env.example`:
```bash
cp .env.example .env
```
Edit `.env` to set your desired ports and secrets:
*   `HONEYPOT_API_KEY`: The secret key for the management dashboard.
*   `PORT_HTTP`, `PORT_SSH`, etc.: The public-facing ports attackers will connect to.

### 2. Launch the System
```bash
docker-compose up -d --build
```
This will start:
*   `honeypot-core`: SSH, HTTP, FTP, Telnet listeners.
*   `honeypot-mgmt`: The FastAPI Backend + React Web Dashboard.
*   `vuln-containers`: Dedicated Node.js and PHP vulnerability decoys.
*   `db-honeypots`: Real MySQL and Redis instances.

---

## 📊 Accessing the Dashboard

### Web Dashboard
Open your browser and navigate to:
`http://localhost:9090`
(Or the port you specified for `PORT_MGMT` in `.env`).
*   The dashboard is automatically protected by your `HONEYPOT_API_KEY`.

### Python TUI (Terminal User Interface)
For monitoring from a terminal, run the included TUI client:
```bash
python3 -m tui
```
Ensure you have set the `HONEYPOT_API_URL` and `HONEYPOT_API_KEY` in your shell environment.

---

## ⚙️ Configuration (`config.yaml`)

The `config.yaml` file controls the behavioral personality of the honeypot:

```yaml
logging:
  level: "INFO"
  sqlite_db: "data/honeypot.db"

# Protocol Port Mapping
protocols:
  ssh:
    port: 10001
    server_header: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
  http:
    port: 10002
    server_hostname: "web-server-prod-01"
```

### Customizing Deception
You can change the `server_header` to mimic different versions of operating systems or services (e.g., swapping OpenSSH for Dropbear).

---

## 🛠️ Maintenance & Troubleshooting

### View Logs
```bash
docker-compose logs -f honeypot
```

### Resetting the Database
To clear all captured attacks and start fresh:
```bash
rm data/honeypot.db && docker-compose restart mgmt
```

### Adding New Vulnerabilities
To add a new vulnerability decoy:
1. Create a new directory in `vulnerabilities/` with a `Dockerfile`.
2. Ensure your app sends logs to `http://mgmt:9090/api/internal/ingest/event`.
3. Add the service to `docker-compose.yml`.
