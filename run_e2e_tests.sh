#!/bin/bash
# Configuration comes from the environment — no credentials in source.
BASE_URL=${VALT_E2E_BASE_URL:-http://localhost:8080}
TESTEMAIL=testrun$(date +%s)@valt.dev
: ${VALT_E2E_PASSWORD:?set VALT_E2E_PASSWORD to run e2e tests}
TESTPASS=${VALT_E2E_PASSWORD}
REGION_CODE=vn
TEST_EMAIL2=testrun2$(date +%s)@valt.dev

TOTAL=0
PASSED=0
FAILED=0

echo "=========================================="
echo "Valt Production E2E Test Suite"
echo "=========================================="
echo ""

echo -n "1.  POST /api/v1/auth/register ...................... "
code=$(curl -s -w "%{http_code}" -o /tmp/r1.txt -X POST "${BASE_URL}/api/v1/auth/register" -H 'Content-Type: application/json' -d "{\"email\":\"$TESTEMAIL\",\"password\":\"$TESTPASS\",\"region_code\":\"$REGION_CODE\"}")
TOTAL=$((TOTAL+1))
if [ "$code" = "201" ] || [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo -n "2.  POST /api/v1/auth/login ......................... "
curl -s -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$TESTEMAIL\",\"password\":\"$TESTPASS\"}" > /tmp/r2.txt
code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$TESTEMAIL\",\"password\":\"$TESTPASS\"}")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
AUTH_TOKEN=$(grep -o '"access_token":"[^"]*' /tmp/r2.txt | head -1 | cut -d'"' -f4)

echo -n "3.  GET /api/v1/orgs ................................ "
curl -s -X GET "${BASE_URL}/api/v1/orgs" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' > /tmp/r3.txt
code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/orgs" -H "Authorization: Bearer $AUTH_TOKEN")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
ORG_ID=$(grep -o '"id":"[a-f0-9-]*' /tmp/r3.txt | head -1 | cut -d'"' -f4)

echo -n "4.  GET /api/v1/orgs/{id} ........................... "
if [ -n "$ORG_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/orgs/$ORG_ID" -H "Authorization: Bearer $AUTH_TOKEN")
  TOTAL=$((TOTAL+1))
  if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "5.  PUT /api/v1/orgs/{id} ........................... "
if [ -n "$ORG_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X PUT "${BASE_URL}/api/v1/orgs/$ORG_ID" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"name":"Test Org Updated"}')
  TOTAL=$((TOTAL+1))
  if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "6.  GET /api/v1/orgs/{id}/workspaces ............... "
if [ -n "$ORG_ID" ]; then
  curl -s -X GET "${BASE_URL}/api/v1/orgs/$ORG_ID/workspaces" -H "Authorization: Bearer $AUTH_TOKEN" > /tmp/r6.txt
  code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/orgs/$ORG_ID/workspaces" -H "Authorization: Bearer $AUTH_TOKEN")
  TOTAL=$((TOTAL+1))
  if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
  WS_ID=$(grep -o '"id":"[a-f0-9-]*' /tmp/r6.txt | head -1 | cut -d'"' -f4)
else
  echo "SKIP"
fi

echo -n "7.  POST /api/v1/workspaces/{ws_id}/projects ....... "
if [ -n "$WS_ID" ]; then
  curl -s -X POST "${BASE_URL}/api/v1/workspaces/$WS_ID/projects" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"name":"Test Project","description":"E2E test"}' > /tmp/r7.txt
  code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/workspaces/$WS_ID/projects" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"name":"Test Project 2","description":"E2E test 2"}')
  TOTAL=$((TOTAL+1))
  if [ "$code" = "201" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
  PROJ_ID=$(grep -o '"id":"[a-f0-9-]*' /tmp/r7.txt | head -1 | cut -d'"' -f4)
else
  echo "SKIP"
fi

echo -n "8.  POST /api/v1/secrets ............................ "
if [ -n "$PROJ_ID" ]; then
  curl -s -X POST "${BASE_URL}/api/v1/secrets" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d "{\"name\":\"test-key\",\"credential_type\":\"api_key\",\"value\":\"sk-test123\",\"project_id\":\"$PROJ_ID\"}" > /tmp/r8.txt
  code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/secrets" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d "{\"name\":\"test-key2\",\"credential_type\":\"api_key\",\"value\":\"sk-test456\",\"project_id\":\"$PROJ_ID\"}")
  TOTAL=$((TOTAL+1))
  if [ "$code" = "201" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
  SECRET_ID=$(grep -o '"id":"[a-f0-9-]*' /tmp/r8.txt | head -1 | cut -d'"' -f4)
else
  echo "SKIP"
fi

echo -n "9.  GET /api/v1/secrets ............................ "
code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/secrets" -H "Authorization: Bearer $AUTH_TOKEN")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo -n "10. GET /api/v1/secrets/{id} ....................... "
if [ -n "$SECRET_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/secrets/$SECRET_ID" -H "Authorization: Bearer $AUTH_TOKEN")
  TOTAL=$((TOTAL+1))
  if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "11. PUT /api/v1/secrets/{id} ....................... "
if [ -n "$SECRET_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X PUT "${BASE_URL}/api/v1/secrets/$SECRET_ID" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"name":"test-key-updated"}')
  TOTAL=$((TOTAL+1))
  if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "12. POST /api/v1/projects/{id}/agents .............. "
if [ -n "$PROJ_ID" ]; then
  curl -s -X POST "${BASE_URL}/api/v1/projects/$PROJ_ID/agents" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"name":"test-agent"}' > /tmp/r12.txt
  code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/projects/$PROJ_ID/agents" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"name":"test-agent2"}')
  TOTAL=$((TOTAL+1))
  if [ "$code" = "201" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
  AGENT_ID=$(grep -o '"id":"[a-f0-9-]*' /tmp/r12.txt | head -1 | cut -d'"' -f4)
else
  echo "SKIP"
fi

echo -n "13. POST /api/v1/agents/{id}/tokens ................ "
if [ -n "$AGENT_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/agents/$AGENT_ID/tokens" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"name":"test-token"}')
  TOTAL=$((TOTAL+1))
  if [ "$code" = "201" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "14. POST /api/v1/me/notification-channels .......... "
code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/me/notification-channels" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"type":"email","config":{"email":"test@example.com"}}')
TOTAL=$((TOTAL+1))
if [ "$code" = "201" ] || [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo -n "15. GET /api/v1/me/notification-channels ........... "
code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/me/notification-channels" -H "Authorization: Bearer $AUTH_TOKEN")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo -n "16. POST /api/v1/me/totp/setup ..................... "
code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/me/totp/setup" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json')
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo -n "17. POST /api/v1/orgs/{id}/webhooks ................ "
if [ -n "$ORG_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/orgs/$ORG_ID/webhooks" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"url":"https://example.com/webhook","events":["secret.created"]}')
  TOTAL=$((TOTAL+1))
  if [ "$code" = "201" ] || [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "18. GET /api/v1/orgs/{id}/webhooks ................. "
if [ -n "$ORG_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/orgs/$ORG_ID/webhooks" -H "Authorization: Bearer $AUTH_TOKEN")
  TOTAL=$((TOTAL+1))
  if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "19. GET /api/v1/orgs/{id}/usage .................... "
if [ -n "$ORG_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/orgs/$ORG_ID/usage" -H "Authorization: Bearer $AUTH_TOKEN")
  TOTAL=$((TOTAL+1))
  if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "20. GET /api/v1/admin/stats ......................... "
code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/api/v1/admin/stats" -H "Authorization: Bearer $AUTH_TOKEN")
TOTAL=$((TOTAL+1))
if [ "$code" = "403" ]; then PASSED=$((PASSED+1)); echo "PASS ($code - expected 403)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo -n "21. POST /api/v1/auth/resend-verification .......... "
code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/auth/resend-verification" -H 'Content-Type: application/json' -d "{\"email\":\"$TESTEMAIL\"}")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ] || [ "$code" = "204" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo -n "22. POST /api/v1/auth/forgot-password .............. "
code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/auth/forgot-password" -H 'Content-Type: application/json' -d "{\"email\":\"$TESTEMAIL\"}")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ] || [ "$code" = "204" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo -n "23. POST /api/v1/orgs/{id}/invitations ............. "
if [ -n "$ORG_ID" ]; then
  code=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${BASE_URL}/api/v1/orgs/$ORG_ID/invitations" -H "Authorization: Bearer $AUTH_TOKEN" -H 'Content-Type: application/json' -d "{\"email\":\"$TEST_EMAIL2\",\"role\":\"member\"}")
  TOTAL=$((TOTAL+1))
  if [ "$code" = "201" ] || [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi
else
  echo "SKIP"
fi

echo -n "24. GET /health .................................... "
code=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${BASE_URL}/health")
TOTAL=$((TOTAL+1))
if [ "$code" = "200" ]; then PASSED=$((PASSED+1)); echo "PASS ($code)"; else FAILED=$((FAILED+1)); echo "FAIL ($code)"; fi

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total:  $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "=========================================="
