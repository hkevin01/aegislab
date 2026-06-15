.PHONY: install dev keys run test lint clean

install:
	pip install -e ".[dev]"

keys:
	@mkdir -p keys
	openssl genrsa -out keys/private.pem 2048
	openssl rsa -in keys/private.pem -pubout -out keys/public.pem
	@echo "Key pair generated in keys/"

dev: keys
	cp -n .env.example .env || true
	docker compose up -d redis
	uvicorn aegislab.api.main:app --reload --port 8000

run:
	uvicorn aegislab.api.main:app --host 0.0.0.0 --port 8000

demo:
	python demo/scenario.py --verbose

test:
	pytest --cov=aegislab --cov-report=term-missing -v

lint:
	ruff check aegislab tests
	mypy aegislab

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache dist build *.egg-info
