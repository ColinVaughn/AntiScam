# AntiScam Bot Makefile
# Provides convenient commands for development and deployment

.PHONY: help setup build start stop restart logs health test clean

# Default target
help:
	@echo "🤖 Discord Anti-Scam Bot - Available Commands"
	@echo "=============================================="
	@echo "setup        - Initial setup and configuration"
	@echo "build        - Build all Docker images"
	@echo "start        - Start all services"
	@echo "stop         - Stop all services"
	@echo "restart      - Restart all services"
	@echo "logs         - Show logs from all services"
	@echo "health       - Run health checks"
	@echo "test         - Run integration tests"
	@echo "clean        - Clean up containers and volumes"
	@echo "dev          - Start development environment"
	@echo ""

# Initial setup
setup:
	@echo "🔧 Setting up AntiScam Bot..."
	@chmod +x scripts/setup.sh
	@./scripts/setup.sh

# Build Docker images
build:
	@echo "🔨 Building Docker images..."
	@docker-compose build

# Start services
start:
	@echo "🚀 Starting all services..."
	@docker-compose up -d

# Stop services
stop:
	@echo "🛑 Stopping all services..."
	@docker-compose down

# Restart services
restart: stop start

# Show logs
logs:
	@echo "📋 Showing service logs..."
	@docker-compose logs -f

# Run health checks
health:
	@echo "🔍 Running health checks..."
	@python3 scripts/health_check.py

# Run integration tests
test:
	@echo "🧪 Running integration tests..."
	@python3 scripts/test_integration.py

# Clean up
clean:
	@echo "🧹 Cleaning up containers and volumes..."
	@docker-compose down -v --remove-orphans
	@docker system prune -f

# Development environment
dev:
	@echo "💻 Starting development environment..."
	@docker-compose up -d postgres redis
	@echo "✅ Database and Redis started"
	@echo "💡 Run individual services with:"
	@echo "   python -m services.bot.main"
	@echo "   python -m services.ocr.main"
	@echo "   python -m services.llm.main" 
	@echo "   python -m services.dashboard.main"

# Service-specific commands
logs-bot:
	@docker-compose logs -f bot

logs-ocr:
	@docker-compose logs -f ocr-service

logs-llm:
	@docker-compose logs -f llm-service

logs-dashboard:
	@docker-compose logs -f dashboard

logs-db:
	@docker-compose logs -f postgres

# Quick status check
status:
	@echo "📊 Service Status:"
	@docker-compose ps
