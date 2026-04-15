# 🏗️ System Architecture & Integration

This document provides a deep dive into the internal mechanics of the Honeypot System, which is built on a **Polyglot Microservice Architecture**.

---

## 🗺️ High-Level Overview

The system is designed as a **Decentralized Layered Honeypot**. Unlike a monolithic application, it is a collection of independent services written in the optimal language for each specific deception task. They coordinate through a centralized management API.

```mermaid
graph TD
    Attacker((Attacker)) --> Node_Bait[Node.js Bait Portal (HTTP/HTTPS)]
    Attacker --> Go_Core[Go Terminal Core (SSH/Telnet)]
    Attacker --> PHP_Mail[PHP SMTP Bait]
    Attacker --> Vuln_Apps[Polyglot Web Traps (Node/PHP)]
    Attacker --> DB_Pots[Database Honeypots (MySQL/Postgres/Mongo/Redis)]

    Node_Bait -- API POST --> Mgmt_API[Node.js/Go Management API]
    Go_Core -- API POST --> Mgmt_API
    PHP_Mail -- API POST --> Mgmt_API
    Vuln_Apps -- API POST --> Mgmt_API
    
    DB_Pots -- Logs --> DB_Parser[DB Log Parser]
    DB_Parser -- Writes --> DB[(Database)]
    Mgmt_API -- Writes --> DB
    
    Mgmt_API -- Serves --> Web_UI[React SysAdmin Dashboard]
```

---

## 📂 Component Breakdown

### 1. The Polyglot Honeypot Core
Instead of a single Python monolith binding all ports, the core relies on specialized microservices:
*   **HTTP & HTTPS (Node.js/Express):** Serves a fully functional prototype web application (the "Synergy Corp" Enterprise Portal) on ports 10002 and 10443. It utilizes genuine Express routing and TLS certificates to provide maximum realism, capturing payloads and credentials natively.
*   **SSH & Telnet (Go):** (Planned Migration) Will utilize native Go TCP and SSH libraries to create a highly realistic Ubuntu terminal emulation, capturing passwords and keystrokes efficiently.
*   **SMTP & FTP (PHP/Go):** Specialized traps designed to capture spam relays, phishing attempts, and file uploads.

### 2. Polyglot Web Traps (`traps/`)
Highly interactive, containerized applications designed to be "broken."
*   **Isolation**: Each app runs in its own Docker container.
*   **Instrumentation**: Apps capture RCE/SQLi payloads natively and POST them to the Management API's ingestion endpoint asynchronously.

### 3. Management API & SysAdmin Dashboard
The central "Brain" of the operation.
*   **FastAPI Backend (Migrating to Node.js/Go)**: Provides REST and WebSocket endpoints for real-time monitoring and high-throughput log ingestion.
*   **Internal Ingest**: Secure endpoint (`/api/internal/ingest/event`) for decentralized vulnerability containers to report activity.
*   **React SysAdmin Dashboard**: A realistic management console providing deep analytics, live logging, and (soon) attacker OSINT tracking.

## 🛠️ Why a Polyglot Architecture?
Running inside Docker allows us to break free from the constraints of a single language like Python.
*   **Realism:** A Python simulated web server (`http.py`) will eventually drop connections or fail to parse complex HTTP/2 requests exactly like a real server would. By using a genuine Node.js Express server or a real PHP backend, we force the attacker to interact with the actual software stack they are trying to exploit.
*   **Performance:** Go handles thousands of concurrent SSH connections far more efficiently than Python's Asyncio loop.
*   **Modularity:** If a specific protocol trap crashes (e.g., due to a complex payload), it does not bring down the entire honeypot network.