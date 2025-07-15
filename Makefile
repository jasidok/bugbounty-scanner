# Makefile
.PHONY: help install test lint format clean docker-build docker-run

help:
	@echo "Bug Bounty Scanner - Make Commands"
	@echo "=================================="
	@echo "install      - Install dependencies"
	@echo "test         - Run tests"
	@echo "lint         - Run linting"
	@echo "format       - Format code"
	@echo "clean        - Clean up generated files"
	@echo "docker-build - Build Docker image"
	@echo "docker-run   - Run Docker container"
	@echo "requirements - Generate requirements.txt"

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

lint:
	flake8 --max-line-length=88 --ignore=E203,W503 .
	black --check .

format:
	black .
	isort .

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/

docker-build:
	docker build -t bug-bounty-scanner .

docker-run:
	docker-compose up -d

requirements:
	python bb_scanner.py --create-requirements

setup:
	python config/default_config.py
	python bb_scanner.py --create-requirements
	@echo "Setup complete! Edit config.json and run 'make install'"