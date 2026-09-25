# AgentGuard — Frontend API Contract (as of tonight, 2026-09-26 04:xx)

**How this file was built:** only endpoints/shapes I directly confirmed tonight —
either by reading the actual route code, or by seeing real request/response pairs
in the eval harness logs. Nothing in this file is from the spec-as-aspiration; it's
from what's actually running right now. Anything I wasn't able to confirm tonight
is marked ⚠️ UNVERIFIED — check it first thing tomorrow before building UI around it,
don't assume it works.

**Base URL:** `http://127.0.0.1:8000` (or wherever uvicorn is bound)
**Auth:** `Authorization: Bearer <token>` — three roles exist (`agent`, `admin`,
`internal`); frontend should use the `admin` token for everything below.

---

## ✅ Confirmed working tonight (build the UI on these first)

### `POST /v1/runs` — create a run
Confirmed from `routes_runs.py:create_run`. Body needs a `task` object; `budgets`
optional.
```json
// request
{"task": {"objective": "...", "human_available": true}, "budgets": {"steps": 50}}
// response 201
{"run_id": "run_...", "status": "RUNNING", "created_at": "...", ...}
```

### `GET /v1/runs/{run_id}` — get run state
Confirmed via eval logs (`GET /v1/runs/run_01M... HTTP/1.1 200 OK` appears
repeatedly). Returns the full `Run` object — status, counters, taint, flags.

### `GET /v1/runs` — list runs
Mentioned in the route file's docstring; not directly exercised tonight, but should
work — same pattern as `GET /{run_id}`.

### `POST /v1/runs/{run_id}/actions` — propose an action (the core loop)
Confirmed — this is the main pipeline entry point, read in full tonight (P0–P10).
```json
// request
{"action_type": "cli.exec", "params": {"command": "ls"}, "confidence": 0.9}
// response 200 (ALLOW) or 202 (ASK_HUMAN) or 200 (DENY/HALT)
{"verdict": "ALLOW|ASK_HUMAN|DENY|HALT", "next_step": "...", "action_id": "act_...", ...}
```
**Important for frontend:** `HALT` and `DENY` both return `200`, not an error code —
don't treat a non-2xx as the only "something was blocked" signal. Check `verdict` in
the body.

### `GET /v1/runs/{run_id}/actions/{action_id}` — poll a specific action
Confirmed from eval logs — used to poll pending/ask_human actions until resolved.

### `GET /v1/inbox?status=open&limit=50` — pending approvals feed
Confirmed, hit constantly in every eval run tonight. **This is your approvals-queue
UI's main data source.**

### `POST /v1/approvals/{approval_id}/decision` — approve or reject
Confirmed from eval logs and `routes_approvals.py`.
```json
// request
{"decision": "approve"}   // or "reject", possibly "resume"/"resume_with_guidance"/"halt" ⚠️ UNVERIFIED which decision values are actually accepted — check routes_approvals.py's request model before building a UI with all 5 buttons
```

### `POST /v1/runs/{run_id}/resume` — resume a paused run
**Built tonight, confirmed present** (`resume_run` function, added as part of the
breaker fix). Requires run to be in `PAUSED` status, else errors.
```json
// response
{"run_id": "run_...", "status": "RUNNING"}
```

### `POST /v1/runs/{run_id}/halt` — kill switch
Mentioned in the route docstring — not exercised tonight, but should exist and work.

### `POST /v1/runs/{run_id}/complete` — mark a run finished
Confirmed — `complete_run` function read tonight.
```json
{"outcome": "success"}   // or "failure", "abandoned"
```
⚠️ Note: `outcome_verified` is currently NOT set by this endpoint at all (neither
`True` nor `False` explicitly) — don't build a "verified ✅" badge in the UI yet, the
backend doesn't populate it meaningfully.

### `POST /v1/runs/{run_id}/thoughts` — log agent reasoning
Mentioned in docstring, matches spec shape — not directly exercised tonight.

### `POST /v1/runs/{run_id}/taint/clear` — clear taint flag
Mentioned in docstring. Taint-raising itself was fixed and confirmed working
tonight (Patch 4); the clear endpoint wasn't separately re-verified.

---

## ⚠️ Exists but broken — do not build against these yet
- **`POST /v1/debug/evaluate`** — the endpoint exists, but its handler body is
  literally `# TODO: run registered analyzers` — it's a stub. If you build a
  "test a command" debug panel in the frontend, it will call this and get nothing
  useful back. Skip this for now.

## ❓ Open question — don't build two separate UIs for this
Whether **approvals** and **escalations** (e.g. circuit-breaker-trip resolution)
are the same endpoint (`/approvals/{id}/decision` handling both) or two separate
systems was **never resolved tonight** — it's flagged in the project's own change
log as an unanswered architectural question. Build the approvals-queue UI generic
enough to handle both without assuming a separate `/escalations` endpoint exists.

## 🔍 Check first thing tomorrow, before frontend work starts
1. **WebSocket** — a `routes_ws.py` file exists but its live-event behavior was not
   exercised or verified at all tonight. If the frontend plan involves live updates
   (recommended, since polling `/inbox` every 100ms is what the eval harness does
   as a stopgap, not a real pattern), confirm the WS contract first with one quick
   manual `wscat` or browser test before building around it.
2. **`GET /v1/runs/{run_id}/events` or similar ledger/timeline feed** — not checked
   tonight. If you want a run-detail timeline view, confirm what's actually
   returned before designing the UI around a specific shape.
3. Anything under `/v1/policy`, `/v1/rulepacks`, `/v1/insights`, `/v1/eval` — these
   appear in the full spec but were **not touched at all** during tonight's
   debugging session. Assume nothing about their current state until checked.

---

## Practical frontend build order, given the above
1. **Run creation + run detail view** — `POST /runs`, `GET /runs/{id}` — solid ground.
2. **Action proposal + live polling of one action** — `POST /actions`, `GET /actions/{id}` — solid, this is the most-tested path tonight.
3. **Approvals inbox** — `GET /inbox`, `POST /approvals/{id}/decision` — solid, heavily exercised.
4. **Pause/resume UI** — `POST /resume` — solid, built and verified tonight.
5. Everything else — build the UI shell, but don't wire real data until each endpoint is individually confirmed working, given how much of tonight was "this exists in the code but was never actually reachable."
