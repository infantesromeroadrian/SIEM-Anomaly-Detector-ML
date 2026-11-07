.PHONY: env help install test lint format reproduce demo-model benchmark frontend-build up

PY ?= .venv/bin/python
SIEM_DATA_DIR ?= $(HOME)/datasets/siem-anomaly
export SIEM_DATA_DIR

help:
	@echo "env           create .env with random local secrets (required by docker compose)"
	@echo "install       create .venv and install dependencies"
	@echo "reproduce     download dataset, train, evaluate -> results/metrics.json + results/report.md + models/"
	@echo "test          pytest with coverage (gate: 70%)"
	@echo "lint          ruff check + ruff format --check"
	@echo "demo-model    train a synthetic DEMO model (API smoke tests only)"
	@echo "benchmark     measure parse+feature+score throughput -> results/benchmark.json"
	@echo "up            docker compose up --build"

env:
	./scripts/init_env.sh

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.lock -e ".[dev]"

reproduce:
	$(PY) -m backend.eval.run --out results --save-model models
	$(PY) -m scripts.benchmark --out results/benchmark.json
	$(PY) -m backend.eval.readme

test:
	$(PY) -m pytest --cov=backend --cov-report=term-missing --cov-fail-under=70

lint:
	.venv/bin/ruff check backend scripts tests
	.venv/bin/ruff format --check backend scripts tests

format:
	.venv/bin/ruff format backend scripts tests

demo-model:
	$(PY) -m scripts.train_demo_model --out models

benchmark:
	$(PY) -m scripts.benchmark --out results/benchmark.json

frontend-build:
	cd frontend && npm ci && npm run build

up:
	docker compose up --build
