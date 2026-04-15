# 🚀 Honeypot System: Future Enhancements & Roadmap

This document outlines the strategic roadmap for evolving the Honeypot System from a modular prototype into a production-grade, AI-driven deception platform.

---

## 💻 Phase 1: Advanced SysAdmin Dashboard Features
*Focus: Upgrading the React frontend to provide deep, actionable insights rather than just raw logs.*

- [ ] **Advanced Interactive Filters**: Implement dynamic filtering across the dashboard. Clicking "Unique Attackers", "Credentials Captured", or "Protocols Active" will instantly filter the event grid to show relevant deep-dive data (e.g., listing exactly *which* credentials were exposed when clicking the credentials card).
- [ ] **Attacker OSINT Integration**: Automatically query external OSINT APIs (e.g., Shodan, IP-API, GreyNoise, VirusTotal) for every unique IP. The dashboard will visually profile attackers, mapping their ASN, country, known malicious history, and associated domains.
- [ ] **Non-HTTP File Management**: Build a "Captured Assets" UI. When an attacker drops a payload via FTP, SSH (`wget`/`scp`), or SMTP (email attachments), the dashboard will allow the SysAdmin to safely view, download, and analyze these files in a sandboxed view.

## 🕸️ Phase 2: Complete the Polyglot Migration
*Focus: Replacing the legacy Python monolith entirely.*

- [ ] **Migrate Management API**: Port the Python FastAPI backend to a highly concurrent Node.js (Express/NestJS) or Go backend to better handle the asynchronous ingestion load from the polyglot containers.
- [ ] **Go-lang SSH/Telnet Trap**: Replace the Python SSH/Telnet handler with a dedicated Go microservice using `gliderlabs/ssh` for maximum concurrent connection handling and perfect terminal emulation.
- [ ] **PHP SMTP Trap**: Replace the Python SMTP handler with a mock PHP mail relay to capture and parse incoming phishing emails.

## 🤖 Phase 3: Intelligence & AI Integration
*Focus: Transforming static bait into adaptive, interactive deception.*

- [ ] **LLM-Powered Orchestrator**: Analyze attacker payloads in real-time using Gemini or OpenAI.
- [ ] **Dynamic Deception**: Generate contextual "honeytokens" (fake AWS keys, DB credentials, or config files) on-the-fly based on what the attacker is searching for.
- [ ] **Interactive Sandboxing**: Enable the AI to "hot-swap" files and environment variables inside the active `nsjail` chroot to keep attackers engaged longer.

## 🛡️ Phase 4: Stealth & Security Hardening
*Focus: Protecting the "Brain" and making the honeypot indistinguishable from a real server.*

- [ ] **Unified Transparent Proxy**: Implement a central ingress (Nginx or a custom Go proxy) that routes traffic to the specific vulnerability containers based on URL paths or Host headers, eliminating the need for suspicious non-standard ports (8081, 8082, etc.).
- [ ] **Strict Egress Filtering**: Implement kernel-level egress rules (iptables/nftables) to ensure the honeypot containers cannot initiate *outbound* connections, preventing the system from being used for real DDoS attacks.

## 📊 Phase 5: Observability & Testing
*Focus: Turning raw logs into actionable threat intelligence and maintaining code quality.*

- [ ] **Strict Testing Protocol**: Ban random port brute-forcing during tests. All testing will utilize targeted, realistic protocol interactions (e.g., `curl -v`, `ssh -p 10001 admin@localhost`).
- [ ] **ELK/Grafana Integration**: Export metrics and events to Prometheus/Grafana for high-performance visual analysis and alerting.

---

> **Note**: These enhancements will position this project as the premier, production-ready honeypot platform in Korea and beyond. Maintain the polyglot philosophy: use the best tool and language for the job.