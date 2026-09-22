# AgentGuard — Autonomous AI System Supervisor and Guardrail

Production-grade backend prototype implementing out-of-band, brokered execution
with deterministic static analysis, a tamper-evident audit ledger, and human-in-the-loop
approval for high-risk agent actions.

## Quick Start

```bash
make setup      # venv + deps + pre-commit
make secrets    # generate AG_* tokens
make up         # docker compose (hub + proxy + sandbox network)
```

## Architecture

See `AGENTGUARD_SPEC_PART_*.md` for the full specification.

## Known Limits (§12.5.2)

1. **Docker socket exposure** — root-equivalent on host; use disposable VM.
2. **Containers are not VMs** — kernel escapes out of scope.
3. **Static shell analysis is not a proof of safety** — sandbox + proxy is the guarantee.
4. **TLS interception** requires CA in sandbox; cert-pinning clients fail closed.
5. **Ledger tamper-evidence, not tamper-proof** — external anchoring is roadmap.
6. **Heuristic checks** can be wrong; they only escalate or advise, never grant power.
7. **Chromium runs with `--no-sandbox`** inside a hardened container.

## Performance Goal and Honesty Rule (§13.1)
AgentGuard is designed as an inline synchronous interceptor for all agent operations. To prevent bottlenecking agent autonomy, the guard guarantees extreme performance: the full pipeline of heuristics and policy evaluation (excluding container spawns/network I/O) executes in under **15 milliseconds (p99)** on modern hardware. If we cannot evaluate it fast enough, we do not evaluate it at all.

## Looking Ahead (Roadmap)
- **External Anchoring**: Committing Ledger Merkle roots to public blockchains for undeniable provenance.
- **eBPF Tracing**: Deeply integrated network capability dropping at the kernel level for executor nodes.
- **Adaptive Timeout Budgets**: Dynamically reallocating milliseconds of evaluation time towards higher-risk operations on the fly.
