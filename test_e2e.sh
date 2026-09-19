#!/bin/bash
# Configuration comes from the environment — no credentials in source.
#   VALT_E2E_BASE_URL    target deployment (default: local compose stack)
#   VALT_E2E_PASSWORD    test password; the script aborts if unset
BASE_URL=${VALT_E2E_BASE_URL:-http://localhost:8080}
TEST_EMAIL=testrun-$(date +%s)@valt.dev
: ${VALT_E2E_PASSWORD:?set VALT_E2E_PASSWORD to run e2e tests}
TEST_PASSWORD=${VALT_E2E_PASSWORD}
REGION_CODE=vn

TOTAL=0
PASSED=0
FAILED=0

# Register
echo -n "1.  POST /api/v1/auth/register ...................... "
resp=$(curl -s -w "%{http_code}" -X POST "${BASE_URL}/api/v1/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"region_code\":\"$REGION_CODE\"}")
code=${resp: -3}
TOTAL=$((TOTAL+1))
if [ "$code" = "201" ] || [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS"; else FAILED=$((FAILED+1)); echo "FAIL"; fi

# Login
echo -n "2.  POST /api/v1/auth/login ......................... "
resp=$(curl -s -X POST "${BASE_URL}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")
code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")
TOTAL=$((TOTAL+1))
AUTH_TOKEN=$(echo "$resp" | grep -o '"access_token":"[^"]*' | head -1 | cut -d'"' -f4)
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS"; else FAILED=$((FAILED+1)); echo "FAIL"; fi

# Get orgs
echo -n "3.  GET /api/v1/orgs ................................ "
code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/orgs" \
  -H "Authorization: Bearer $AUTH_TOKEN")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS"; else FAILED=$((FAILED+1)); echo "FAIL"; fi

# Health check
echo -n "4.  GET /health .................................... "
code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/health")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS"; else FAILED=$((FAILED+1)); echo "FAIL"; fi

echo ""
echo "Total: $TOTAL | Passed: $PASSED | Failed: $FAILED"
