# AgentGuard — Demo Setup Guide

> **Goal:** Get the full AgentGuard stack (backend hub + frontend dashboard) running on any laptop in under 10 minutes.

---

## Prerequisites

Install these once on the demo laptop:

| Tool | Version | Download |
|------|---------|----------|
| **Python** | ≥ 3.11 | https://www.python.org/downloads/ |
| **Node.js** | ≥ 18 | https://nodejs.org/ |
| **Git** | any | https://git-scm.com/ |
| **Docker Desktop** | latest | https://www.docker.com/products/docker-desktop/ *(optional for full sandbox eval)* |

> **Docker is optional for the demo.** The hub and frontend run fine without it. Docker is only needed if you want to trigger live `cli.exec` action sandboxing.

---

## Step 1 — Clone both repos

```bash
# Backend
git clone https://github.com/Anujsoni-2005/agentguard.git
cd agentguard
```

For the **frontend**, copy the `agentguard-—-autonomous-oversight` folder to the demo laptop (zip it and transfer via USB / Google Drive / email).

---

## Step 2 — Set up the Backend (AgentGuard Hub)

### 2a. Create a virtual environment

```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python -m venv .venv
source .venv/bin/activate
```

### 2b. Install Python dependencies

```bash
pip install -r requirements-hub.txt
```

> If this fails on `mitmproxy`, skip it — it's not needed for the demo:
> ```bash
> pip install fastapi uvicorn[standard] pydantic pydantic-settings aiosqlite httpx python-ulid structlog pyahocorasick PyYAML tenacity orjson pynacl tree-sitter tree-sitter-bash bashlex tldextract
> ```

### 2c. Create the `.env` file

Create a file named `.env` in the `agentguard/` folder:

```env
AG_AGENT_TOKEN=dev-agent-token
AG_ADMIN_TOKEN=dev-admin-token
AG_INTERNAL_TOKEN=dev-internal-token
AG_SERVER_SECRET=0123456789012345678901234567890123456789
```

### 2d. Start the Hub

```bash
python -m uvicorn agentguard.hub.app:create_app --factory --host 127.0.0.1 --port 8000
```

**Verify:**
```bash
curl http://127.0.0.1:8000/v1/health
# Expected: {"status": "ok"}
```

---

## Step 3 — Set up the Frontend Dashboard

Open a **new terminal** (keep the hub running).

```bash
cd "agentguard-—-autonomous-oversight"

npm install --legacy-peer-deps

npm run dev
```

Open **http://localhost:3000** in your browser.

When both are running, a **green banner** appears:
> ✅ Connected to AgentGuard Hub — live data active.

---

## Step 4 — Automated Demo Walkthrough

Once the backend hub is running, you can run the automated demo script to simulate an agent proposing actions, including unauthorized writes and prompt injections:

Open a **new terminal** (keep the hub running):

```bash
cd agentguard
# Windows (PowerShell)
.\demo.ps1
```

Watch the terminal output as the hub processes the agent's actions, and view the live results on your frontend dashboard!

---

## Step 5 — Manual Demo Walkthrough

### ✅ Flow 1: Approvals Inbox
1. Click **Inbox** in the left sidebar
2. Pending approvals from the backend appear here (polls every 5s)
3. Click **Approve** or **Reject** — real API call to the hub

### ✅ Flow 2: Active Runs Monitor
1. Click **Active Runs** → select any run
2. See live step history, cost, tokens
3. Click **Resume Run** if a run is paused

### ✅ Flow 3: Launch a New Mission
1. Click **+ New Run** in the sidebar
2. Enter an objective, set budget
3. Click **Launch Mission** — creates a real run on the hub
4. Redirected to the Run Monitor automatically

### `U` Upcoming (mock-only — still safe to demo)
- **Policies & Guardrails** — rule list UI, local only
- **Execution Traces** — trace view using run state
- **Settings** — UI preview, not persisted

---

## Quick Commands (All-in-One Reference)

```bash
# ── Terminal 1: Backend ───────────────────────────────
cd agentguard

# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS/Linux
python -m venv .venv && source .venv/bin/activate

pip install -r requirements-hub.txt
python -m uvicorn agentguard.hub.app:create_app --factory --host 127.0.0.1 --port 8000

# ── Terminal 2: Frontend ──────────────────────────────
cd "agentguard-—-autonomous-oversight"
npm install --legacy-peer-deps
npm run dev

# ── Open browser ──────────────────────────────────────
# http://localhost:3000
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Hub won't start | Make sure `.env` exists in `agentguard/` root |
| `npm install` fails | Use `npm install --legacy-peer-deps` |
| Frontend shows amber banner | Hub is not running — check Terminal 1 |
| CORS error in browser | Add `AG_CORS_ORIGINS=http://localhost:3000` to `.env` |
| Port 8000 already in use | Kill the existing process or use `--port 8001` and update `apiClient.ts` |
| `pip install` fails on Windows with `mitmproxy` | Skip it, install remaining packages manually (see Step 2b) |
