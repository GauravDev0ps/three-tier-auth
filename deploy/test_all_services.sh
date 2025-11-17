#!/bin/bash
################################################################################
# Three-Tier Auth Services - Integration Test Script
# Tests all services and their interactions
################################################################################

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BASE_URL=${BASE_URL:-"http://localhost"}
KGAAS_PORT=${KGAAS_PORT:-8001}
UIDAAAS_PORT=${UIDAAAS_PORT:-5000}
DMIUAAS_PORT=${DMIUAAS_PORT:-6000}
LACRYPTAAS_PORT=${LACRYPTAAS_PORT:-8002}

TEST_USER="testuser_$(date +%s)"
TEST_EMAIL="test_$(date +%s)@example.com"
TEST_PASSWORD="TestP@ssw0rd123!"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

print_section() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
}

# Test function
test_endpoint() {
    local name=$1
    local url=$2
    local method=${3:-GET}
    local data=$4
    local expected_status=${5:-200}
    
    print_test "$name"
    
    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST "$url" \
            -H "Content-Type: application/json" \
            -d "$data" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null)
    fi
    
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$status_code" = "$expected_status" ]; then
        print_pass "$name (Status: $status_code)"
        echo "$body"
        return 0
    else
        print_fail "$name (Expected: $expected_status, Got: $status_code)"
        echo "$body"
        return 1
    fi
}

print_section "HEALTH CHECKS"

# Test KGaaS
test_endpoint "KGaaS Health Check" "$BASE_URL:$KGAAS_PORT/ping"

# Test UIDAaaS
test_endpoint "UIDAaaS Health Check" "$BASE_URL:$UIDAAAS_PORT/ping"

# Test DMIUAaas
test_endpoint "DMIUAaas Health Check" "$BASE_URL:$DMIUAAS_PORT/ping"

# Test Lacryptaas
test_endpoint "Lacryptaas Health Check" "$BASE_URL:$LACRYPTAAS_PORT/ping"

print_section "KGAAS TESTS"

# Test key creation
print_test "Creating encryption key"
KEY_RESPONSE=$(curl -s -X POST "$BASE_URL:$KGAAS_PORT/v1/keys" \
    -H "Content-Type: application/json" \
    -H "X-Api-Key: demo-secret-token" \
    -d '{"allowed_services": ["lacryptaas", "uidaaas"], "ttl_seconds": 3600}')

KEY_ID=$(echo "$KEY_RESPONSE" | grep -o '"key_id":"[^"]*"' | cut -d'"' -f4)

if [ -n "$KEY_ID" ]; then
    print_pass "Key created: $KEY_ID"
else
    print_fail "Failed to create key"
fi

# Test key retrieval
if [ -n "$KEY_ID" ]; then
    test_endpoint "Retrieve key by ID" "$BASE_URL:$KGAAS_PORT/v1/keys/$KEY_ID" "GET" "" "200"
fi

# Test list keys
test_endpoint "List all keys" "$BASE_URL:$KGAAS_PORT/v1/keys" "GET" "" "200"

print_section "LACRYPTAAS TESTS"

# Test encryption
print_test "Encrypting data"
ENCRYPT_RESPONSE=$(curl -s -X POST "$BASE_URL:$LACRYPTAAS_PORT/encrypt" \
    -H "Content-Type: application/json" \
    -d '{"plaintext": "Hello Three-Tier Auth System!", "mode": "cbc"}')

ENCRYPTION_KEY_ID=$(echo "$ENCRYPT_RESPONSE" | grep -o '"key_id":"[^"]*"' | cut -d'"' -f4)
IV=$(echo "$ENCRYPT_RESPONSE" | grep -o '"iv_b64":"[^"]*"' | cut -d'"' -f4)
CIPHERTEXT=$(echo "$ENCRYPT_RESPONSE" | grep -o '"ciphertext_b64":"[^"]*"' | cut -d'"' -f4)

if [ -n "$CIPHERTEXT" ] && [ -n "$IV" ]; then
    print_pass "Data encrypted successfully"
    echo "Key ID: $ENCRYPTION_KEY_ID"
    echo "IV: ${IV:0:20}..."
    echo "Ciphertext: ${CIPHERTEXT:0:30}..."
else
    print_fail "Encryption failed"
fi

# Test decryption
if [ -n "$CIPHERTEXT" ] && [ -n "$IV" ] && [ -n "$ENCRYPTION_KEY_ID" ]; then
    print_test "Decrypting data"
    DECRYPT_RESPONSE=$(curl -s -X POST "$BASE_URL:$LACRYPTAAS_PORT/decrypt" \
        -H "Content-Type: application/json" \
        -d "{\"key_id\": \"$ENCRYPTION_KEY_ID\", \"iv_b64\": \"$IV\", \"ciphertext_b64\": \"$CIPHERTEXT\", \"mode\": \"cbc\"}")
    
    PLAINTEXT=$(echo "$DECRYPT_RESPONSE" | grep -o '"plaintext":"[^"]*"' | cut -d'"' -f4)
    
    if [ "$PLAINTEXT" = "Hello Three-Tier Auth System!" ]; then
        print_pass "Decryption successful: $PLAINTEXT"
    else
        print_fail "Decryption failed or wrong plaintext"
    fi
fi

# Test GCM mode encryption
print_test "Encrypting with GCM mode"
GCM_RESPONSE=$(curl -s -X POST "$BASE_URL:$LACRYPTAAS_PORT/encrypt" \
    -H "Content-Type: application/json" \
    -d '{"plaintext": "GCM test message", "mode": "gcm"}')

if echo "$GCM_RESPONSE" | grep -q "nonce_b64"; then
    print_pass "GCM encryption successful"
else
    print_fail "GCM encryption failed"
fi

print_section "UIDAAAS TESTS"

# Test access request
print_test "Requesting access"
REQUEST_RESPONSE=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/request_access" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$TEST_EMAIL\", \"username\": \"$TEST_USER\"}")

REQUEST_ID=$(echo "$REQUEST_RESPONSE" | grep -o '"request_id":[0-9]*' | cut -d':' -f2)

if [ -n "$REQUEST_ID" ]; then
    print_pass "Access requested (Request ID: $REQUEST_ID)"
else
    print_fail "Access request failed"
fi

# Test OTP creation
if [ -n "$REQUEST_ID" ]; then
    print_test "Creating OTP for registration"
    OTP_RESPONSE=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/create_user_from_request" \
        -H "Content-Type: application/json" \
        -d "{\"request_id\": $REQUEST_ID}")
    
    OTP_TOKEN=$(echo "$OTP_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$OTP_TOKEN" ]; then
        print_pass "OTP created: ${OTP_TOKEN:0:20}..."
    else
        print_fail "OTP creation failed"
    fi
fi

# Test user registration
if [ -n "$OTP_TOKEN" ]; then
    print_test "Finalizing user registration"
    FINALIZE_RESPONSE=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/finalize_registration" \
        -H "Content-Type: application/json" \
        -d "{\"token\": \"$OTP_TOKEN\", \"password\": \"$TEST_PASSWORD\", \"username\": \"$TEST_USER\"}")
    
    if echo "$FINALIZE_RESPONSE" | grep -q "user created"; then
        print_pass "User registered: $TEST_USER"
    else
        print_fail "User registration failed"
        echo "$FINALIZE_RESPONSE"
    fi
fi

# Test login
print_test "Testing user login"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$TEST_USER\", \"password\": \"$TEST_PASSWORD\"}")

if echo "$LOGIN_RESPONSE" | grep -q "login successful"; then
    print_pass "Login successful"
else
    print_fail "Login failed"
fi

# Test invalid login
print_test "Testing invalid login (should fail)"
INVALID_LOGIN=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$TEST_USER\", \"password\": \"WrongPassword123!\"}")

if echo "$INVALID_LOGIN" | grep -q "invalid credentials"; then
    print_pass "Invalid login correctly rejected"
else
    print_fail "Invalid login should have been rejected"
fi

# Test list users
test_endpoint "List users" "$BASE_URL:$UIDAAAS_PORT/list_users"

print_section "DMIUAAS TESTS"

# Test pattern registration
print_test "Registering image pattern"
PATTERN_RESPONSE=$(curl -s -X POST "$BASE_URL:$DMIUAAS_PORT/register_user_secret" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$TEST_USER\", \"pattern\": [[0,1], [2,3], [1,2]]}")

if echo "$PATTERN_RESPONSE" | grep -q "Pattern registered"; then
    print_pass "Pattern registered for $TEST_USER"
else
    print_fail "Pattern registration failed"
    echo "$PATTERN_RESPONSE"
fi

# Test challenge initialization
print_test "Initializing image challenge"
CHALLENGE_RESPONSE=$(curl -s -X POST "$BASE_URL:$DMIUAAS_PORT/init_image_challenge" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$TEST_USER\"}")

CHALLENGE_TOKEN=$(echo "$CHALLENGE_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -n "$CHALLENGE_TOKEN" ]; then
    print_pass "Challenge created: ${CHALLENGE_TOKEN:0:20}..."
    
    # Show grid info
    GRID=$(echo "$CHALLENGE_RESPONSE" | grep -o '"grid":' | wc -l)
    if [ "$GRID" -gt 0 ]; then
        echo "  Grid successfully generated"
    fi
else
    print_fail "Challenge creation failed"
fi

# Test challenge verification (correct pattern)
if [ -n "$CHALLENGE_TOKEN" ]; then
    print_test "Verifying image challenge (correct pattern)"
    VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL:$DMIUAAS_PORT/verify_image_challenge" \
        -H "Content-Type: application/json" \
        -d "{\"token\": \"$CHALLENGE_TOKEN\", \"selected_positions\": [[0,1], [2,3], [1,2]]}")
    
    if echo "$VERIFY_RESPONSE" | grep -q '"success":true'; then
        print_pass "Challenge verification successful"
    else
        print_fail "Challenge verification failed"
        echo "$VERIFY_RESPONSE"
    fi
fi

# Test get pattern info
test_endpoint "Get pattern info" "$BASE_URL:$DMIUAAS_PORT/get_user_pattern_info?username=$TEST_USER"

print_section "INTEGRATION TESTS"

# Test full authentication flow
print_test "Full authentication workflow"
WORKFLOW_USER="workflow_$(date +%s)"
WORKFLOW_EMAIL="workflow_$(date +%s)@example.com"

# 1. Request access
REQ=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/request_access" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$WORKFLOW_EMAIL\", \"username\": \"$WORKFLOW_USER\"}")
REQ_ID=$(echo "$REQ" | grep -o '"request_id":[0-9]*' | cut -d':' -f2)

# 2. Create OTP
OTP=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/create_user_from_request" \
    -H "Content-Type: application/json" \
    -d "{\"request_id\": $REQ_ID}")
TOKEN=$(echo "$OTP" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# 3. Finalize registration
FIN=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/finalize_registration" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$TOKEN\", \"password\": \"$TEST_PASSWORD\"}")

# 4. Register image pattern
PAT=$(curl -s -X POST "$BASE_URL:$DMIUAAS_PORT/register_user_secret" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$WORKFLOW_USER\", \"pattern\": [[0,0], [1,1], [2,2]]}")

# 5. Login
LOG=$(curl -s -X POST "$BASE_URL:$UIDAAAS_PORT/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$WORKFLOW_USER\", \"password\": \"$TEST_PASSWORD\"}")

# 6. Complete image challenge
CHA=$(curl -s -X POST "$BASE_URL:$DMIUAAS_PORT/init_image_challenge" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$WORKFLOW_USER\"}")
CHA_TOKEN=$(echo "$CHA" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

VER=$(curl -s -X POST "$BASE_URL:$DMIUAAS_PORT/verify_image_challenge" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$CHA_TOKEN\", \"selected_positions\": [[0,0], [1,1], [2,2]]}")

if echo "$VER" | grep -q '"success":true'; then
    print_pass "Full workflow completed successfully"
else
    print_fail "Full workflow failed at challenge verification"
fi

print_section "TEST SUMMARY"

TOTAL=$((TESTS_PASSED + TESTS_FAILED))
SUCCESS_RATE=$(awk "BEGIN {print ($TESTS_PASSED/$TOTAL)*100}")

echo ""
echo "Tests Passed:  $TESTS_PASSED"
echo "Tests Failed:  $TESTS_FAILED"
echo "Total Tests:   $TOTAL"
echo "Success Rate:  ${SUCCESS_RATE}%"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    exit 1
fi