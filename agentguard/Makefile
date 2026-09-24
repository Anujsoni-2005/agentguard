.PHONY: setup test lint format up down clean

setup:
	python -m venv .venv
	.venv/Scripts/python -m pip install --upgrade pip
	.venv/Scripts/python -m pip install -e ".[dev]"

test:
	.venv/Scripts/pytest -v

lint:
	.venv/Scripts/ruff check .
	.venv/Scripts/mypy .

format:
	.venv/Scripts/ruff format .

up:
	# stub for docker compose

clean:
	Remove-Item -Recurse -Force .venv -ErrorAction SilentlyContinue
	Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue
	Remove-Item -Recurse -Force .ruff_cache -ErrorAction SilentlyContinue
	Remove-Item -Recurse -Force .mypy_cache -ErrorAction SilentlyContinue
	Remove-Item -Recurse -Force data -ErrorAction SilentlyContinue

bench:
	.venv/Scripts/python -m agentguard.bench

demo:
	@echo "--- AGENTGUARD DEMO RUNBOOK REHEARSAL ---"
	@echo "1. Initialize guard and check UI for zero configuration state."
	@echo "2. Simulate an unauthorized filesystem write to /etc/shadow, observe DENY."
	@echo "3. Simulate an autonomous prompt injection, observe ASK_HUMAN override."
	@echo "4. Export the cryptographic ledger proving the exact sequence of events."
	@echo "5. Validate the offline bundle using tools/verify_bundle.py."
	@echo "Demo Rehearsal Complete."
