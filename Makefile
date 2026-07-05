# Security-Ops — developer & ops entry points (see README "Make targets").
#
#   make dev      run the API locally with --reload on :8130 (scripts/dev.sh)
#   make migrate  apply DB migrations locally (alembic upgrade head)
#   make seed     seed the pilot org/target/engagement + prove the gate (in-container)
#   make test     run the test suite (pytest)
#   make build    docker compose build
#   make up       docker compose up -d
#   make down     docker compose down   (add `-v` yourself to also drop the DB volume)

COMPOSE     ?= docker compose
API_SERVICE ?= secops-api
PYTEST_ARGS ?=

.DEFAULT_GOAL := help
.PHONY: help dev migrate seed test build up down

help:
	@echo "targets: dev migrate seed test build up down"

dev:
	./scripts/dev.sh

migrate:
	alembic upgrade head

seed:
	$(COMPOSE) exec $(API_SERVICE) python -m scripts.seed_pilot

test:
	python -m pytest $(PYTEST_ARGS)

test-deps:
	pip install -r requirements.txt -r requirements-dev.txt

build:
	$(COMPOSE) build

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down
