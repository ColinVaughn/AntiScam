#!/bin/bash

# AntiScam Bot Setup Script
# This script sets up the complete environment for the Discord Anti-Scam Bot

set -e

echo "🤖 Discord Anti-Scam Bot Setup"
echo "=============================="

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are available"

# Check if .env file exists
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your Discord bot token and settings before continuing"
    echo "   Required: DISCORD_TOKEN, DISCORD_CLIENT_ID"
    echo "   Optional: Adjust other settings as needed"
    echo ""
    read -p "Press Enter when you've configured .env file..."
fi

# Create required directories
echo "📁 Creating directories..."
mkdir -p models
mkdir -p logs
mkdir -p temp_images

# Check if model file exists
if [ ! -f models/quantized_model.gguf ]; then
    echo "🔍 No LLM model found. You need to download a quantized model."
    echo "   Example: wget https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.q4_0.gguf -O models/quantized_model.gguf"
    echo "   Or use any other GGUF format model"
    echo ""
    read -p "Download a model to models/quantized_model.gguf and press Enter..."
fi

# Build and start services
echo "🔨 Building Docker images..."
docker-compose build

echo "🚀 Starting services..."
docker-compose up -d postgres redis

# Wait for database to be ready
echo "⏳ Waiting for database to start..."
sleep 10

# Start other services
echo "🚀 Starting all services..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to initialize..."
sleep 15

# Run health check
echo "🔍 Running health checks..."
python3 scripts/health_check.py

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Invite your bot to Discord servers with these permissions:"
echo "   - Manage Messages"
echo "   - Read Message History" 
echo "   - Send Messages"
echo "   - Add Reactions"
echo "   - View Channels"
echo ""
echo "2. Access the dashboard at: http://localhost:8080"
echo "3. Configure per-server settings via dashboard or Discord commands"
echo "4. Monitor logs with: docker-compose logs -f"
echo ""
echo "Discord Commands:"
echo "  !scamconfig show           - Show current configuration"
echo "  !scamconfig set <key> <value> - Update settings"
echo "  !scamstats                 - Show detection statistics"
echo ""
echo "Troubleshooting:"
echo "  docker-compose logs <service> - Check service logs"
echo "  python3 scripts/health_check.py - Run health checks"
