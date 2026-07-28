.PHONY: dev up down migrate lint test all

dev:
	uvicorn app.main:app --reload --port 8080

up:
	docker compose up -d --build

down:
	docker compose down -v

migrate:
	alembic upgrade head

lint:
	ruff check .
	mypy app

test:
	pytest -q

all: lint test
