.PHONY: help setup run stop clean test format

help:
	@echo "Honeypot Development Commands"
	@echo "-----------------------------"
	@echo "make setup    - Create virtual environment and setup .env"
	@echo "make run      - Run honeypot and management api using docker-compose"
	@echo "make stop     - Stop docker-compose services"
	@echo "make clean    - Remove build artifacts, pycache and venv"
	@echo "make format   - Run black formatter"

setup:
	@echo "Setting up local development environment..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from .env.example"; fi
	@if [ ! -d .venv ]; then python3 -m venv .venv; echo "Created virtual environment .venv"; fi
	@./.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
	@echo "Setup complete! Remember to activate your venv: source .venv/bin/activate"

run:
	docker-compose up -d --build

stop:
	docker-compose down

clean:
	rm -rf .venv
	rm -rf data/*.log data/*.db
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "build" -exec rm -rf {} +
	find . -type d -name "dist" -exec rm -rf {} +
	@echo "Cleaned up workspace"

format:
	./.venv/bin/black honeypot/ api/ tui/ analyzer/
