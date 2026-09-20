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
