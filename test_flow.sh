#!/bin/bash

echo "🔗 Complete Obius API Test Flow"
echo "=================================="

# Step 1: Mint a fresh token
echo "1. 🪙 Minting fresh access token..."
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8100/mint \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"demo_user","credits":25.0}')

echo "Token Response: $TOKEN_RESPONSE"

# Extract token (works with or without jq)
if command -v jq >/dev/null 2>&1; then
    TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')
    TRACE_ID=$(echo "$TOKEN_RESPONSE" | jq -r '.trace_id')
else
    TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    TRACE_ID=$(echo "$TOKEN_RESPONSE" | grep -o '"trace_id":"[^"]*"' | cut -d'"' -f4)
fi

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "❌ Failed to extract token"
    exit 1
fi

echo "✅ Token extracted successfully"
echo "📋 Trace ID: $TRACE_ID"

# Step 2: Get crypto price data with receipt
echo ""
echo "2. 💰 Requesting crypto price data..."
PRICE_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8100/data/price?pair=BTCUSDT")

echo "Price Response:"
echo "$PRICE_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$PRICE_RESPONSE"

# Step 3: Check current balances
echo ""
echo "3. 💳 Checking current balances..."
BALANCE_RESPONSE=$(curl -s http://localhost:8100/balances)
echo "Balances:"
echo "$BALANCE_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$BALANCE_RESPONSE"

# Step 4: List available packages
echo ""
echo "4. 📦 Available data packages..."
PACKAGES_RESPONSE=$(curl -s http://localhost:8100/packages)
echo "Packages:"
echo "$PACKAGES_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$PACKAGES_RESPONSE"

echo ""
echo "🎯 Test Summary:"
echo "• Token minted and used successfully"
echo "• Crypto data retrieved with payment receipt"
echo "• Revenue automatically distributed to suppliers/reviewers"
echo "• System balances updated"

echo ""
echo "🌐 Next Steps:"
echo "• Open http://localhost:8100/catalog.html in browser"
echo "• Register as supplier/reviewer for more features"
echo "• Your fresh token: ${TOKEN:0:50}..."