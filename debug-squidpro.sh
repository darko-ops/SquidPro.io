#!/bin/bash

echo "🔍 SquidPro Debug Information"
echo "============================"

echo "📊 Container Status:"
docker compose ps

echo ""
echo "🌐 Port Status:"
echo "Port 8100 (API):"
lsof -i :8100 || echo "   No process on port 8100"
echo "Port 8200 (Crypto):"
lsof -i :8200 || echo "   No process on port 8200"
echo "Port 5432 (PostgreSQL):"
lsof -i :5432 || echo "   No process on port 5432"

echo ""
echo "📝 Recent Logs (last 20 lines per service):"
echo "--- SquidPro API ---"
docker compose logs --tail=20 squidpro-api 2>/dev/null || echo "No squidpro-api logs"

echo ""
echo "--- Crypto Collector ---"
docker compose logs --tail=20 collector-crypto 2>/dev/null || echo "No collector-crypto logs"

echo ""
echo "--- PostgreSQL ---"
docker compose logs --tail=20 postgres 2>/dev/null || echo "No postgres logs"

echo ""
echo "🧪 Quick Connectivity Tests:"
echo "Direct API test:"
curl -s http://localhost:8100/health || echo "   Cannot reach API"

echo ""
echo "Direct crypto test:"
curl -s http://localhost:8200/price || echo "   Cannot reach crypto service"

echo ""
echo "🐋 Docker Info:"
echo "Docker version:"
docker --version

echo ""
echo "Docker Compose version:"
docker compose version

echo ""
echo "�� File Check:"
echo "Current directory: $(pwd)"
echo "Files present:"
ls -la | grep -E "(docker-compose|Dockerfile|app\.py|schema\.sql)"

echo ""
echo "🔧 Suggested Actions:"
echo "1. If containers aren't running: docker compose up --build -d"
echo "2. If services are failing: docker compose logs -f"
echo "3. If ports are occupied: docker compose down && docker compose up -d"
echo "4. If database issues: docker compose down -v && docker compose up -d"
