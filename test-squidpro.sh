#!/bin/bash

echo "🧪 Testing SquidPro System"
echo "=========================="

API_BASE="http://localhost:8100"
CRYPTO_BASE="http://localhost:8200"

# Test 1: Health checks
echo "1. �� Health Checks"
echo "   API Health:"
if curl -s "$API_BASE/health" >/dev/null 2>&1; then
    HEALTH_RESPONSE=$(curl -s "$API_BASE/health")
    echo "   ✅ SquidPro API is healthy: $HEALTH_RESPONSE"
else
    echo "   ❌ SquidPro API health check failed"
    echo "   Check if the service is running: docker compose ps"
fi

echo "   Crypto Collector:"
if curl -s "$CRYPTO_BASE/price" >/dev/null 2>&1; then
    echo "   ✅ Crypto Collector is healthy"
else
    echo "   ❌ Crypto Collector health check failed"
fi

# Test 2: Data packages
echo ""
echo "2. 📦 Data Packages"
PACKAGES_RESPONSE=$(curl -s "$API_BASE/packages" 2>/dev/null)
if [ $? -eq 0 ] && echo "$PACKAGES_RESPONSE" | grep -q "\["; then
    if command -v jq >/dev/null 2>&1; then
        COUNT=$(echo "$PACKAGES_RESPONSE" | jq length 2>/dev/null || echo "unknown")
    else
        COUNT="unknown (jq not installed)"
    fi
    echo "   ✅ Found $COUNT data packages"
else
    echo "   ❌ Failed to fetch packages"
    echo "   Response: $PACKAGES_RESPONSE"
fi

# Test 3: Token minting
echo ""
echo "3. 🪙 Token Minting"
TOKEN_RESPONSE=$(curl -s -X POST "$API_BASE/mint" \
    -H "Content-Type: application/json" \
    -d '{"agent_id":"test_agent","credits":10.0}' 2>/dev/null)

if [ $? -eq 0 ] && echo "$TOKEN_RESPONSE" | grep -q "token"; then
    echo "   ✅ Token minted successfully"
    if command -v jq >/dev/null 2>&1; then
        TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token' 2>/dev/null)
    else
        TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    fi
    
    if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
        # Test 4: Authenticated data access
        echo ""
        echo "4. 🔐 Authenticated Data Access"
        DATA_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$API_BASE/data/price?pair=BTCUSDT" 2>/dev/null)
        
        if [ $? -eq 0 ] && echo "$DATA_RESPONSE" | grep -q "price"; then
            if command -v jq >/dev/null 2>&1; then
                PRICE=$(echo "$DATA_RESPONSE" | jq -r '.price' 2>/dev/null)
            else
                PRICE=$(echo "$DATA_RESPONSE" | grep -o '"price":[^,}]*' | cut -d':' -f2)
            fi
            echo "   ✅ Successfully accessed price data: $PRICE"
        else
            echo "   ❌ Failed to access authenticated data"
            echo "   Response: $DATA_RESPONSE"
        fi
    else
        echo "   ❌ Token extraction failed"
    fi
else
    echo "   ❌ Token minting failed"
    echo "   Response: $TOKEN_RESPONSE"
fi

# Test 5: Registration (demo)
echo ""
echo "5. 👤 Registration Test"
RANDOM_NUM=$(date +%s)
REG_RESPONSE=$(curl -s -X POST "$API_BASE/suppliers/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"Test Supplier $RANDOM_NUM\",
        \"email\": \"test$RANDOM_NUM@example.com\",
        \"stellar_address\": \"GDXDSB444OLNDYOJAVGU3JWQO4BEGQT2MCVTDHLOWORRQODJJXO3GBDU\"
    }" 2>/dev/null)

if [ $? -eq 0 ] && echo "$REG_RESPONSE" | grep -q "api_key"; then
    echo "   ✅ Supplier registration successful"
    if command -v jq >/dev/null 2>&1; then
        API_KEY=$(echo "$REG_RESPONSE" | jq -r '.api_key' 2>/dev/null)
    else
        API_KEY=$(echo "$REG_RESPONSE" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)
    fi
    echo "   📝 API Key: ${API_KEY:0:20}..."
else
    echo "   ❌ Supplier registration failed"
    echo "   Response: $REG_RESPONSE"
fi

echo ""
echo "🎯 Test Summary Complete"
echo "========================"
echo "• Check all ✅ marks above for successful tests"
echo "• Any ❌ marks indicate issues that need attention"
echo "• Access the web interface at: http://localhost:8100"
echo ""
echo "🔧 Troubleshooting:"
echo "• View container status: docker compose ps"
echo "• View logs: docker compose logs"
echo "• Restart services: docker compose restart"
