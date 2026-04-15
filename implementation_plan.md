# Polyglot Backend Reconstruction & System Enhancements

## Objective
Address the user's vision to make this the "In-Korea Best Honeypot Platform" by completely reconstructing the backend architecture. We will abandon the monolithic Python implementation (`src/backend/core` and `src/backend/api`) in favor of a genuine, multi-language microservice architecture utilizing Node.js, Go, PHP, etc. This ensures maximum realism and leverages Docker's containerization to its fullest.

## Full Architectural Reconstruction Plan

### Phase 1: Git Workflow & Context Initialization
1. **Branching:** Create and checkout a new branch `feature/polyglot-backend-reconstruction` to isolate this massive overhaul.
2. **Context Maintenance:** This very document will serve as the uncompacted context and roadmap. It will be saved into the repository as `implementation_plan.md` to ensure zero loss of context for future development steps.

### Phase 2: Deconstruct the Python Monolith
The current Python backend is split into two main parts: the Management API (FastAPI) and the Honeypot Core (Asyncio TCP). We will replace both with specialized polyglot microservices.

#### 1. The Management API (Migrating to Node.js or Go)
- **Current:** Python FastAPI (`src/backend/api/`).
- **New Architecture:** We will build a high-performance **Node.js (Express) or Go** Management API. 
- **Responsibility:** Ingest JSON logs from all vulnerable traps, store them in the database (SQLite/Mongo), and serve the React frontend (`src/frontend/`) for the SysAdmin Dashboard.
- **Why?** Node.js/Go handles asynchronous I/O and web requests natively and scales better for high-throughput log ingestion than the current Python setup.

#### 2. The Honeypot Core (Migrating to Polyglot Microservices)
Instead of one Python process binding 6 ports, we will spin up dedicated containers written in the best language for the job.
- **HTTP & HTTPS Bait (Port 10002, 10443):**
  - **Language:** Node.js.
  - **Implementation:** A fully functional, user-accessible prototype web application serving as the "Synergy Corp" Enterprise Portal. Because HTTP/HTTPS is the primary entry point for attackers, this bait will not just be a static login page. It will feature multiple fake routes, a realistic frontend UI (React or plain HTML/JS), dummy API endpoints, and realistic SSL/TLS certificates. All interactions will silently log to the new backend.
- **SSH & Telnet Bait (Port 10001, 10004):**
  - **Language:** Go.
  - **Implementation:** Utilizing native Go TCP and SSH libraries (e.g., `gliderlabs/ssh`) to create a highly realistic Ubuntu terminal emulation that captures passwords and keystrokes.
- **FTP Bait (Port 10003):**
  - **Language:** C or Go (e.g., a heavily instrumented fork of `vsftpd` or a custom Go FTP server).
- **SMTP Bait (Port 10005):**
  - **Language:** PHP or Node.js.
  - **Implementation:** A mock mail relay that captures incoming spam/phishing payloads.

### Phase 3: SysAdmin Dashboard & Future Enhancements
Once the backend is reconstructed, we will implement the requested SysAdmin features:
1. **Advanced Filters:** Clickable metrics ("Unique Attackers", "Credentials Captured", "Protocols Active") that filter the web dashboard dynamically.
2. **OSINT Integration:** Automatically query OSINT APIs (e.g., IP-API, Shodan) to profile unique attackers and display this rich data on the dashboard.
3. **Non-HTTP File Management:** Add a dashboard view allowing SysAdmins to see and manage files uploaded via the FTP, SSH, and SMTP traps.
4. **Testing Protocol:** Ban random port brute-forcing during tests; all testing will use targeted, realistic protocol interactions (e.g., `curl`, `ssh`).

### Phase 4: Documentation Overhaul
- **`README.md`:** Stripped down to pure usage, overview, and quickstart commands (`./manage.sh start`).
- **`docs/architecture.md` & `docs/ENHANCEMENTS.md`:** Fully populated with the elaborate details of this new polyglot architecture, language choices, and the OSINT/Dashboard plans. 

## Execution Strategy
- **Step-by-Step:** Do not get buried in one process. If a specific language implementation hangs or is too complex, kill the process, re-evaluate, and move to the next service. Keep the "forest" in view.
- **Root Cause & Judgement:** Make autonomous judgments on the best library or framework to use for each microservice based on realism and stability. 
- **Merge Strategy:** After completing the polyglot migration and verifying all services log successfully to the new Management API, merge the `feature/polyglot-backend-reconstruction` branch into `main`.