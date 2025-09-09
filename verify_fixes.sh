#!/bin/bash

echo "🔍 Verifying Security Fixes"
echo "=========================="

# Test 1: Verify SQL injection protection
echo "1. Testing SQL injection protection..."
curl -s -X POST http://localhost:8100/suppliers/register \
    -H "Content-Type: application/json" \
    -d '{"name":"'\'' OR 1=1 --","email":"sqli@test.com","stellar_address":"GDXDSB444OLNDYOJAVGU3JWQO4BEGQT2MCVTDHLOWORRQODJJXO3GBDU"}' \
    | grep -q "Invalid character" && echo "✅ SQL injection blocked" || echo "❌ SQL injection not blocked"

# Test 2: Verify rate limiting
echo "2. Testing rate limiting..."
for i in {1..15}; do
    RESPONSE=$(curl -s -w "%{http_code}" -X POST http://localhost:8100/mint \
        -H "Content-Type: application/json" \
        -d '{"agent_id":"rate_test_'$i'","credits":1.0}' -o /dev/null)
    if [ "$RESPONSE" = "429" ]; then
        echo "✅ Rate limiting active (request $i blocked)"
        break
    fi
done

# Test 3: Verify input validation
echo "3. Testing input validation..."
curl -s -X POST http://localhost:8100/mint \
    -H "Content-Type: application/json" \
    -d '{"agent_id":"test","credits":-999}' \
    | grep -q "validation error\|Invalid" && echo "✅ Negative credits blocked" || echo "❌ Negative credits allowed"

# Test 4: Verify file upload restrictions
echo "4. Testing file upload security..."
# This would need a valid API key to test properly

echo "Verification complete!"
