#!/usr/bin/env python3
"""E2E smoke tests. Configuration comes from the environment — no credentials
in source: VALT_E2E_BASE_URL (default local compose stack) and
VALT_E2E_PASSWORD (required)."""
import os
import subprocess
import json
import time

BASE_URL = os.environ.get("VALT_E2E_BASE_URL", "http://localhost:8080")
TEST_EMAIL = f"testrun-{int(time.time())}@valt.dev"
TEST_PASSWORD = os.environ["VALT_E2E_PASSWORD"]
REGION_CODE = "vn"
TEST_EMAIL_2 = f"testrun2-{int(time.time())}@valt.dev"

total_tests = 0
passed_tests = 0
failed_tests = 0

def curl_req(method, endpoint, expected_status, data=None, auth_token=None, public=False):
    global total_tests, passed_tests, failed_tests

    url = f"{BASE_URL}{endpoint}"
    cmd = ["curl", "-s", "-w", "%{http_code}", "-X", method, url, "-H", "Content-Type: application/json"]

    if auth_token and not public:
        cmd.extend(["-H", f"Authorization: Bearer {auth_token}"])

    if data:
        cmd.extend(["-d", json.dumps(data)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout
        code = int(output[-3:])
        total_tests += 1

        status = "PASS" if code == expected_status else "FAIL"
        if status == "PASS":
            passed_tests += 1
        else:
            failed_tests += 1

        body = output[:-3] if len(output) > 3 else ""
        return code, body, status
    except Exception as e:
        total_tests += 1
        failed_tests += 1
        return 0, "", "ERROR"

def extract_id(body):
    try:
        data = json.loads(body)
        if isinstance(data, list) and len(data) > 0:
            return data[0].get("id")
        return data.get("id")
    except:
        return None

print("=" * 60)
print("Valt Production E2E Test Suite")
print("=" * 60)
print()

auth_token = None
org_id = None
ws_id = None
proj_id = None
secret_id = None
agent_id = None

# Test 1: Register
print("1.  POST /api/v1/auth/register ...................... ", end="", flush=True)
code, body, status = curl_req("POST", "/api/v1/auth/register", 201,
    {"email": TEST_EMAIL, "password": TEST_PASSWORD, "region_code": REGION_CODE}, public=True)
print(f"{status} ({code})")

# Test 2: Login
print("2.  POST /api/v1/auth/login ......................... ", end="", flush=True)
code, body, status = curl_req("POST", "/api/v1/auth/login", 200,
    {"email": TEST_EMAIL, "password": TEST_PASSWORD}, public=True)
print(f"{status} ({code})")
if status == "PASS" and body:
    try:
        data = json.loads(body)
        auth_token = data.get("access_token")
    except:
        pass

# Test 3: Get orgs
print("3.  GET /api/v1/orgs ................................ ", end="", flush=True)
code, body, status = curl_req("GET", "/api/v1/orgs", 200, auth_token=auth_token)
print(f"{status} ({code})")
if status == "PASS":
    org_id = extract_id(body)

# Test 4: Get org detail
print("4.  GET /api/v1/orgs/{id} ........................... ", end="", flush=True)
if org_id:
    code, body, status = curl_req("GET", f"/api/v1/orgs/{org_id}", 200, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 5: Update org
print("5.  PUT /api/v1/orgs/{id} ........................... ", end="", flush=True)
if org_id:
    code, body, status = curl_req("PUT", f"/api/v1/orgs/{org_id}", 200,
        {"name": "Test Org Updated"}, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 6: Get workspaces
print("6.  GET /api/v1/orgs/{id}/workspaces ............... ", end="", flush=True)
if org_id:
    code, body, status = curl_req("GET", f"/api/v1/orgs/{org_id}/workspaces", 200, auth_token=auth_token)
    print(f"{status} ({code})")
    if status == "PASS":
        ws_id = extract_id(body)
else:
    print("SKIP")

# Test 7: Create project
print("7.  POST /api/v1/workspaces/{ws_id}/projects ....... ", end="", flush=True)
if ws_id:
    code, body, status = curl_req("POST", f"/api/v1/workspaces/{ws_id}/projects", 201,
        {"name": "Test Project", "description": "E2E test"}, auth_token=auth_token)
    print(f"{status} ({code})")
    if status == "PASS":
        proj_id = extract_id(body)
else:
    print("SKIP")

# Test 8: Create secret
print("8.  POST /api/v1/secrets ............................ ", end="", flush=True)
if proj_id:
    code, body, status = curl_req("POST", "/api/v1/secrets", 201,
        {"name": "test-key", "credential_type": "api_key", "value": "sk-test123", "project_id": proj_id},
        auth_token=auth_token)
    print(f"{status} ({code})")
    if status == "PASS":
        secret_id = extract_id(body)
else:
    print("SKIP")

# Test 9: List secrets
print("9.  GET /api/v1/secrets ............................ ", end="", flush=True)
code, body, status = curl_req("GET", "/api/v1/secrets", 200, auth_token=auth_token)
print(f"{status} ({code})")

# Test 10: Get single secret
print("10. GET /api/v1/secrets/{id} ....................... ", end="", flush=True)
if secret_id:
    code, body, status = curl_req("GET", f"/api/v1/secrets/{secret_id}", 200, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 11: Update secret
print("11. PUT /api/v1/secrets/{id} ....................... ", end="", flush=True)
if secret_id:
    code, body, status = curl_req("PUT", f"/api/v1/secrets/{secret_id}", 200,
        {"name": "test-key-updated"}, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 12: Create agent
print("12. POST /api/v1/projects/{id}/agents .............. ", end="", flush=True)
if proj_id:
    code, body, status = curl_req("POST", f"/api/v1/projects/{proj_id}/agents", 201,
        {"name": "test-agent"}, auth_token=auth_token)
    print(f"{status} ({code})")
    if status == "PASS":
        agent_id = extract_id(body)
else:
    print("SKIP")

# Test 13: Issue agent token
print("13. POST /api/v1/agents/{id}/tokens ................ ", end="", flush=True)
if agent_id:
    code, body, status = curl_req("POST", f"/api/v1/agents/{agent_id}/tokens", 201,
        {"name": "test-token"}, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 14: Add notification channel
print("14. POST /api/v1/me/notification-channels .......... ", end="", flush=True)
code, body, status = curl_req("POST", "/api/v1/me/notification-channels", 201,
    {"type": "email", "config": {"email": "test@example.com"}}, auth_token=auth_token)
print(f"{status} ({code})")

# Test 15: List notification channels
print("15. GET /api/v1/me/notification-channels ........... ", end="", flush=True)
code, body, status = curl_req("GET", "/api/v1/me/notification-channels", 200, auth_token=auth_token)
print(f"{status} ({code})")

# Test 16: Setup TOTP
print("16. POST /api/v1/me/totp/setup ..................... ", end="", flush=True)
code, body, status = curl_req("POST", "/api/v1/me/totp/setup", 200, auth_token=auth_token)
print(f"{status} ({code})")

# Test 17: Create webhook
print("17. POST /api/v1/orgs/{id}/webhooks ................ ", end="", flush=True)
if org_id:
    code, body, status = curl_req("POST", f"/api/v1/orgs/{org_id}/webhooks", 201,
        {"url": "https://example.com/webhook", "events": ["secret.created"]}, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 18: List webhooks
print("18. GET /api/v1/orgs/{id}/webhooks ................. ", end="", flush=True)
if org_id:
    code, body, status = curl_req("GET", f"/api/v1/orgs/{org_id}/webhooks", 200, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 19: Get usage
print("19. GET /api/v1/orgs/{id}/usage .................... ", end="", flush=True)
if org_id:
    code, body, status = curl_req("GET", f"/api/v1/orgs/{org_id}/usage", 200, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 20: Admin stats (should be 403 for non-admin)
print("20. GET /api/v1/admin/stats ......................... ", end="", flush=True)
code, body, status = curl_req("GET", "/api/v1/admin/stats", 403, auth_token=auth_token)
print(f"{status} ({code}) [expected 403]")

# Test 21: Resend verification
print("21. POST /api/v1/auth/resend-verification .......... ", end="", flush=True)
code, body, status = curl_req("POST", "/api/v1/auth/resend-verification", 200,
    {"email": TEST_EMAIL}, public=True)
print(f"{status} ({code})")

# Test 22: Forgot password
print("22. POST /api/v1/auth/forgot-password .............. ", end="", flush=True)
code, body, status = curl_req("POST", "/api/v1/auth/forgot-password", 200,
    {"email": TEST_EMAIL}, public=True)
print(f"{status} ({code})")

# Test 23: Invite team member
print("23. POST /api/v1/orgs/{id}/invitations ............. ", end="", flush=True)
if org_id:
    code, body, status = curl_req("POST", f"/api/v1/orgs/{org_id}/invitations", 201,
        {"email": TEST_EMAIL_2, "role": "member"}, auth_token=auth_token)
    print(f"{status} ({code})")
else:
    print("SKIP")

# Test 24: Health check
print("24. GET /health .................................... ", end="", flush=True)
code, body, status = curl_req("GET", "/health", 200, public=True)
print(f"{status} ({code})")

print()
print("=" * 60)
print(f"Total Tests:  {total_tests}")
print(f"Passed:       {passed_tests}")
print(f"Failed:       {failed_tests}")
print("=" * 60)
