# 🍯 Polyglot Deception Network

A production-grade, multi-language honeypot network featuring genuine polyglot architectures, real backing databases, and an interconnected "Enterprise User Portal" bait.

## 🚀 Quick Start

Ensure Docker and Make are installed, then provision everything simultaneously.

```bash
# Provide environment variables (ports, API keys)
cp .env.example .env

# Build and start the entire Polyglot network in the background
./manage.sh start

# View the SysAdmin analytics dashboard
http://localhost:9090

# View the attacker-facing bait portal (Synergy Corp)
http://localhost:10002
```

## 📚 Documentation

Detailed documentation is available in the `docs/` directory:
- [Motivation & Philosophy](docs/motivation.md): Why this project was built and the design principles behind it.
- [Usage Guide](docs/usage.md): Step-by-step instructions for deployment, configuration, and monitoring.
- [Architecture Deep-Dive](docs/architecture.md): Detailed explanation of how the different components (Core, API, Vulnerabilities, DB) interact.
- [Future Enhancements](docs/ENHANCEMENTS.md): The roadmap for upcoming features and research directions.

## 🛠️ Management Script (`manage.sh`)

A convenient management script is provided to handle the lifecycle of the honeypot services.

```bash
Usage: ./manage.sh [command]

Commands:
  start       - Start the honeypot services in the background
  stop        - Stop and remove the honeypot containers
  restart     - Restart the honeypot services
  status      - Show the status of all honeypot containers
  healthcheck - Check if the honeypot containers are running and healthy
  logs        - View the logs of all honeypot containers
  clean       - Stop services and remove associated volumes and networks
```

## 📂 Project Structure

```text
.
├── config.yaml               # Global Honeypot Settings & Protocol Flags
├── docker-compose.yml        # Multi-Container Orchestration definition
├── docs/                     # Detailed technical documentation
├── infrastructure/           # Dockerfiles and server configs (planned)
├── src/                      # Source code (backend core, API, CLI tools, frontend)
│   ├── backend/
│   │   ├── api/              # FastAPI Management App
│   │   ├── cli/              # Log Analysis & TUI
│   │   └── core/             # Asyncio TCP Server (SSH, HTTP, FTP, Telnet, SMTP)
│   └── frontend/             # React/Vite Frontend Web Dashboard
├── traps/                    # Separated Polyglot Microservices (Node.js & PHP traps)
└── manage.sh                 # Management script
```
