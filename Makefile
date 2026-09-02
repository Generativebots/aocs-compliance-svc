# Makefile — aocs-compliance-svc
# Run `make help` for usage.

BINARY      := aocs-compliance
SERVICE     := aocs-compliance
PORT        := 8089
MODULE      := github.com/ocx/compliance

.PHONY: help build run test lint docker-build docker-run clean db-deploy

help:
	@echo "aocs-compliance-svc Makefile"
	@echo ""
	@echo "  make build        Build binary"
	@echo "  make run          Run locally (requires .env)"
	@echo "  make test         Run all tests"
	@echo "  make lint         Run golangci-lint"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-run   Start with docker compose"
	@echo "  make db-deploy    Deploy compliance schema to Supabase"
	@echo "  make clean        Remove build artifacts"

build:
	go build -ldflags="-w -s" -o bin/$(BINARY) ./cmd/$(BINARY)

run:
	@if [ ! -f .env ]; then echo "Missing .env — copy .env.example"; exit 1; fi
	export $$(grep -v '^#' .env | xargs) && go run ./cmd/$(BINARY)

test:
	go test ./... -v -race -timeout 120s

lint:
	golangci-lint run ./...

docker-build:
	docker build -t $(SERVICE):local .

docker-run:
	docker compose up -d

db-deploy:
	@echo "=== Deploying compliance schema to Supabase ==="
	@echo "Run these files in order in Supabase Dashboard → SQL Editor:"
	@echo "  1. database/schema/00_gen_id_function.sql"
	@echo "  2. database/schema/00_compliance_schema.sql"
	@echo "  3. database/schema/01_tables.sql"
	@echo "  4. database/schema/04_triggers.sql"
	@echo "  5. database/schema/05_indexes.sql"
	@echo "  6. database/schema/06_policies.sql"
	@echo "  7. database/seeds/00_seed_controls.sql"

clean:
	rm -rf bin/
