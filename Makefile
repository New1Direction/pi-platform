.PHONY: help install dev test test-all lint format docker-build docker-up clean

help:
	@echo "PI Platform — Deterministic Semantic Execution Kernel"
	@echo ""
	@echo "Targets:"
	@echo "  install        Create venv and install all dependencies"
	@echo "  dev            Install with dev extras"
	@echo "  test           Run all test suites"
	@echo "  test-core      Run core runtime tests only"
	@echo "  test-conformance Run 26 spec conformance tests"
	@echo "  test-console   Run console boundary tests"
	@echo "  lint           Run ruff and mypy"
	@echo "  format         Auto-format with ruff"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-up      Run console + core in Docker"
	@echo "  clean          Remove build artifacts"

install:
	pip install -e .

dev:
	pip install -e ".[dev,all]"

test:
	PYTHONPATH=src python -m pytest tests -q --tb=short

test-core:
	PYTHONPATH=src python -m pytest tests/unit -q --tb=short

test-conformance:
	PYTHONPATH=src:tests/conformance python -m pytest tests/conformance/test_conformance.py -v --tb=short

test-console:
	PYTHONPATH=src python -m pytest tests/console -v --tb=short

lint:
	ruff check src tests
	mypy src --ignore-missing-imports

format:
	ruff format src tests

docker-build:
	docker compose -f docker/docker-compose.yml build

docker-up:
	docker compose -f docker/docker-compose.yml up

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
