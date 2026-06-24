# 🛡️ CyberGuard AI - Intelligent Incident Detection & Automated Containment

**CyberGuard AI** is a state-of-the-art incident detection, automatic threat containment, and security orchestration system. It parses system authentication logs to identify failed logins or brute-force threat vectors in real-time, validates threat actors against external reputation databases, dynamically applies containment policies, syncs logs to a Notion database, and provides a beautiful control room dashboard.

---

## 🌟 Key Features

### 🤖 Intelligent Multi-Agent Orchestration
*   `ThreatAnalyzer`: Evaluates raw auth log sequence frequencies, identifying security breaches or brute force patterns.
*   `ResponseAgent`: Initiates automated containment pipelines.
*   `RollbackAgent`: Safely unblocks firewall blocks and reverts containment states.

### 🔌 Gated External Integrations
*   **ArmorClaw Integration:** Conducts real-time reputational scans on suspicious IP addresses.
*   **ArmorIQ Integration:** Dynamically evaluates security actions against policy rules before executing containment.
*   **Notion Database Sync:** Automatically records incident statuses, risk scores, timelines, and audit/compliance reports in a persistent database.

### 🖥️ Premium Glassmorphic Web Dashboard
*   **Overview Hub:** Live metric charts (Critical, High, Medium severities), calendar events timeline, and an interactive **Threat Heatmap Grid** showing weekly hourly alert densities.
*   **Security Console:** The central command interface containing live controls to run log simulations and view live incident feeds.
*   **Firewall Controls:** Center to add manual blocks, unblock IPs, and inspect active firewall states.
*   **Audit Trail:** Chronological log tracking all containment, scan completions, and rollback operations.
*   **AI Security Copilot:** An interactive chatbot helper to request count reports, query policy rules, and summarize logs in plain English.

### 🛡️ Safety-First & Global Reversion (Undo)
*   **Global Undo Rule:** Every single automated and manual action in CyberGuard AI is built with rollback safety. Revert firewall blocks, checklist tasks, chat clears, settings adjustments, and upgrade plans with a single click.

### 💎 Flexible Protection Subscriptions
*   **Weekly Pass ($9.99/week)**: Quick short-term auditing or threat sequence verification.
*   **Monthly Pro ($29.99/month)**: Active deployments, Notion database sync, and AI Copilot capabilities.
*   **Yearly Enterprise ($249.99/year)**: Unlimited nodes, priority support, and auto-generated compliance reports.
*   *Note: Subscriptions are stored securely in browser `localStorage` and feature dynamic visual highlighting inside the plans modal.*

---

## 🛠️ Technical Stack

- **Backend:** Python, FastAPI, Uvicorn, Pydantic, Requests
- **Frontend:** HTML5, Vanilla CSS3 (Custom Variables, Neon Glows, Translucent Glassmorphism), Vanilla JS SPA
- **Testing:** Pytest / Unittest Test Suite
- **Deployment:** Vercel Edge Serverless Functions

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have Python 3.10+ installed on your system.

### 2. Installation
Clone this repository and navigate to the project directory:
```bash
git clone https://github.com/UTSAV1434/cyberguard-2.0.git
cd cyberguard-2.0
```

Install the required dependencies:
```bash
pip install -r requirements.txt
```

### 3. Configuration
Copy `.env.template` to a new file named `.env`:
```bash
cp .env.template .env
```
Open `.env` and fill in your integration credentials:
*   Set `MOCK_MODE=True` to run the system offline with local mock database simulation.
*   Set `MOCK_MODE=False` and fill in `NOTION_TOKEN`, `NOTION_DATABASE_ID`, `ARMORIQ_API_KEY`, and `ARMORCLAW_API_KEY` to run against live endpoints.

### 4. Running the Dashboard Server
Start the FastAPI server locally:
```bash
python server.py
```
By default, the dashboard will be hosted at `http://127.0.0.1:8000`.

### 5. Running the Simulation CLI
You can run automated auth log threat analysis directly via the command-line CLI:
```bash
python main.py run-simulation --file sample_logs/auth_failures.json
```

To list current firewall blocks:
```bash
python main.py show-blocks
```

To rollback/undo a specific incident block:
```bash
python main.py undo --incident-id <incident-id> --reason "False Positive"
```

---

## 🧪 Testing
Run the automated unit and API test suite to verify that all systems are functioning correctly:
```bash
python -m unittest discover tests
```

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
