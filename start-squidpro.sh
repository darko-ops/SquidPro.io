#!/bin/bash

echo "🚀 Starting Obius Data Marketplace"
echo "====================================="

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker compose down

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads
mkdir -p public

# Build and start services
echo "🔨 Building and starting services..."
docker compose up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 15

# Check service health
echo "🔍 Checking service health..."

# Check PostgreSQL
if docker compose exec postgres pg_isready -U obius >/dev/null 2>&1; then
    echo "✅ PostgreSQL is ready"
else
    echo "❌ PostgreSQL is not ready"
fi

# Check collector-crypto
if curl -s http://localhost:8200/price >/dev/null 2>&1; then
    echo "✅ Crypto Collector is ready"
else
    echo "❌ Crypto Collector is not ready"
fi

# Check obius-api
if curl -s http://localhost:8100/health >/dev/null 2>&1; then
    echo "✅ Obius API is ready"
else
    echo "❌ Obius API is not ready"
fi

echo ""
echo "🌐 Access Points:"
echo "   • API: http://localhost:8100"
echo "   • Health: http://localhost:8100/health"
echo "   • Catalog: http://localhost:8100/catalog.html"
echo "   • Profile: http://localhost:8100/profile.html"
echo ""
echo "📊 Service Status:"
docker compose ps

echo ""
echo "🧪 Quick Tests:"
echo "Test crypto data: curl http://localhost:8200/price"
echo "Test API health: curl http://localhost:8100/health"
echo "View logs: docker compose logs -f"
