# Makefile for managing Docker Compose environments

ENV ?= dev

ENV_FILE = .env.$(ENV)
COMPOSE_FILE = docker-compose.$(ENV).yml

up:
	docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE) up -d

down:
	docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE) down

logs:
	docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE) logs -f

ps:
	docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE) ps

build:
	docker compose --env-file $(ENV_FILE) -f $(COMPOSE_FILE) build

restart:
	make down ENV=$(ENV)
	make up ENV=$(ENV)