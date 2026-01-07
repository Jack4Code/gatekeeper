.PHONY: help build run test clean db-setup db-migrate docker-build docker-run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the gatekeeper binary
	@echo "Building gatekeeper..."
	@go build -o gatekeeper .

run: ## Run gatekeeper (requires .env file)
	@echo "Starting gatekeeper..."
	@export $$(cat .env | xargs) && go run . serve

test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

clean: ## Remove built binaries
	@echo "Cleaning..."
	@rm -f gatekeeper

deps: ## Install/update dependencies
	@echo "Installing dependencies..."
	@go mod tidy
	@go mod download

db-setup: ## Create database and user (requires psql)
	@echo "Setting up database..."
	@createdb authdb || echo "Database may already exist"
	@psql -d authdb -c "CREATE USER authuser WITH PASSWORD 'authpass';" || echo "User may already exist"
	@psql -d authdb -c "GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;"

db-migrate-up: ## Run pending database migrations
	@echo "Running migrations..."
	@export $$(cat .env | xargs) && go run . migrate up --type postgres

db-migrate-down: ## Rollback last migration
	@echo "Rolling back migration..."
	@export $$(cat .env | xargs) && go run . migrate down --type postgres

db-migrate-status: ## Show migration status
	@echo "Checking migration status..."
	@export $$(cat .env | xargs) && go run . migrate status --type postgres

db-migrate-create: ## Create a new migration (usage: make db-migrate-create NAME=my_migration)
	@if [ -z "$(NAME)" ]; then \
		echo "Error: NAME is required. Usage: make db-migrate-create NAME=my_migration"; \
		exit 1; \
	fi
	@echo "Creating migration: $(NAME)"
	@go run . migrate create $(NAME) --type postgres

db-reset: ## Drop and recreate database (WARNING: destroys data)
	@echo "Resetting database..."
	@dropdb authdb || true
	@make db-setup
	@make db-migrate-up

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t gatekeeper:latest .

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	@docker run -p 8080:8080 -p 9090:9090 --env-file .env gatekeeper:latest

dev: ## Run with hot reload (requires air: go install github.com/cosmtrek/air@latest)
	@air

.env: ## Create .env from .env.example
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env file. Please edit it with your configuration."; \
	else \
		echo ".env file already exists"; \
	fi