#!/usr/bin/env bash
# =============================================================================
# EUDI Wallet - Relying Party (RP) Test Harness & Integration Simulator (ERP-THIS)
#
# This script will automate the demonstration of a full cross-device
# presentation flow against the Express-based test verification server
# implementation.
# 
# It will execute the following steps automatically vi curl & jq:
# 1. Session initiation (GET /api/presentation/initiate)
# 2. Extraction of session ID (state) and the cryptographic nonce
# 3. Constructing a valid direct_post payload (using Erika Mustermann mockup)
#   - signed SD-JWT VC (tamper-proof identity credential)
#   - selectve disclosures of identity properties
#   - device key binding (JWT-based holder binding proof) bound to session nonce
# 4. Transmission of direct_post callback (POST /spi/presentation/callback)
# 5. Query of server-side onboarding status (GET /api/presentation/status)
# =============================================================================

set -euo pipefail

# Configuration properties
API_BASE="http://localhost:3000"
COLOR_RESET="\033[0m"
COLOR_INFO="\033[34m"
COLOR_SUCCESS="\033[32m"
COLOR_WARN="\033[33m"
COLOR_ERROR="\033[31m"

echo -e "${COLOR_INFO}=== EUDI WALLET TEST HARNESS SIMULATOR ===${COLOR_RESET}"
echo "Checking if express backend is running..."

# Check if express backend server is up and running
if ! curl -s --head --request GET "${API_BASE}/api/presentation/initiate" > /dev/null; then
    echo -e "${COLOR_ERROR}ERROR: express backend at ${API_BASE} not reachable!${COLOR_RESET}"
    echo "Please start the server first via: node eudi-verifier-server.js"
    exit 1
fi

# Check if jq command is available
if ! command -v jq &> /dev/null; then
    echo -e "${COLOR_ERROR}ERROR: 'jq' is not installed. Please install it in order to run this script.${COLOR_RESET}"
    exit 1
fi

# -----------------------------------------------------------------------------
# STEP 1: session initialization
# -----------------------------------------------------------------------------
echo -e "\n${COLOR_INFO}[Step 1/4] Initiating server-side presenation session...${COLOR_RESET}"
INIT_RESPONSE=$(curl -s "${API_BASE}/api/presentation/initiate")

# Extraction of parameters
SESSION_ID=$(echo "$INIT_RESPONSE" | jq -r '.sessionId')
QR_CODE_URL=$(echo "$INIT_RESPONSE" | jq -r '.qrCodeUrl')

echo -e "${COLOR_SUCCESS}✔ Session successfully initiated!${COLOR_RESET}"
echo "  - Session ID (state): $SESSION_ID"
echo "  - QR code content:    $QR_CODE_URL"

# -----------------------------------------------------------------------------
# STEP 2: Retrieve request object meta data (JAR)
# -----------------------------------------------------------------------------
echo -e "\n${COLOR_INFO}[Step 2/4] Simulating wallet: retruieving request object (JAR) via request_uri...${COLOR_RESET}"
# parsing request_uri from the openid4vp URI
REQUEST_URI=$(echo "$QR_CODE_URL" | grep -o 'request_uri=[^&]*' | cut -d'=' -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")

# Retrieve signed request JWT
SIGNED_JAR=$(curl -s "$REQUEST_URI")

# Decoding JWT playload to get verifier nonce
JAR_PAYLOAD_BASE64=$(echo "$SIGNED_JAR" | cut -d'.' -f2)
JAR_PAYLOAD=$(echo "$JAR_PAYLOAD_BASE64" | tr '-_' '+/' | base64 --decode 2>/dev/null || echo "$JAR_PAYLOAD_BASE64" | tr '-_' '+/' | base64 -d 2>/dev/null)
NONCE=$(echo "$JAR_PAYLOAD" | jq -r '.nonce')

echo -e "${COLOR_SUCCESS}✔ Request Object (JAR) retrieved and decoded!${COLOR_RESET}"
echo "  - extracted transaction nonce: $NONCE"

# -----------------------------------------------------------------------------
# STEP 3: Cryptographic holder binding proof (mock)
# -----------------------------------------------------------------------------
echo -e "\n${COLOR_INFO}[Step 3/4] Erika Mustermann | prepare direct_post payload...${COLOR_RESET}"

# 1. Issuer-signed JWT (header & payload w/ claim hashes)
ISSUER_HEADER_B64=$(echo -n '{"alg":"ES256","typ":"dc+sd-jwt"}' | base64 | tr -d '\r\n=' | tr '+/' '-_')
ISSUER_PAYLOAD_B64=$(echo -n "{\"iss\":\"https://registry.government.de/pid-issuer\",\"iat\":$(date +%s),\"exp\":$(( $(date +%s) + 3600 )),\"vct\":\"https://credentials.example.com/identity_credential\",\"_sd_alg\":\"sha-256\",\"_sd\":[\"jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4\",\"TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo\"],\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\",\"y\":\"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"}}}" | base64 | tr -d '\r\n=' | tr '+/' '-_')
ISSUER_SIGNATURE_B64="simulated_government_issuer_signature"
ISSUER_JWT="${ISSUER_HEADER_B64}.${ISSUER_PAYLOAD_B64}.${ISSUER_SIGNATURE_B64}"

# 2. Disclosures (clear-test values & salts)
# Disclosure 1: given_name -> ["salt123", "given_name", "Erika"]
DISCLOSURE_1=$(echo -n '["2GLC42sKQveCfGfryNRN9w", "given_name", "Erika"]' | base64 | tr -d '\r\n=' | tr '+/' '-_')
# Disclosure 2: family_name -> ["salt456", "family_name", "family_name", "Mustermann"]
DISCLOSURE_2=$(echo -n '["eluV5Og3gSNII8EYnsxA_A", "family_name", "Mustermann"]' | base64 | tr -d '\r\n=' | tr '+/' '-_')
# Disclosure 3: birthdate -> ["salt789", "birthdate", "1998-08-12"]
DISCLOSURE_3=$(echo -n '["6Ij7tM-a5iVPGboS5tmvVA", "birthdate", "1998-08-12"]' | base64 | tr -d '\r\n=' | tr '+/' '-_')
# Disclosure 4: is_over_18 -> ["saltabc", "is_over_18", true]
DISCLOSURE_4=$(echo -n '["Pc33JM2LchcU_lHggv_ufQ", "is_over_18", true]' | base64 | tr -d '\r\n=' | tr '+/' '-_')
# Disclosure 5: address -> ["saltdef", "address", {...}]
DISCLOSURE_5=$(echo -n '["Qg_O64zqAxe412a108iroA", "address", {"street_address": "Heidestraße 17", "locality": "Köln", "postal_code": "50667", "country": "DE"}]' | base64 | tr -d '\r\n=' | tr '+/' '-_')

# 3. Key Binding JWT (Holder Binding Proof, signed with device key)
KB_HEADER_B64=$(echo -n '{"alg":"ES256","typ":"kb+jwt"}' | base64 | tr -d '\r\n=' | tr '+/' '-_')
KB_PAYLOAD_B64=$(echo -n "{\"nonce\":\"$NONCE\",\"aud\":\"x509_san_dns:client.example.org\",\"iat\":$(date +%s),\"sd_hash\":\"Dy-RYwZfaaoC3inJbLslgPvMp09bH-clYP_3qbRqtW4\"}" | base64 | tr -d '\r\n=' | tr '+/' '-_')
KB_SIGNATURE_B64="simulated_device_secure_element_signature"
KB_JWT="${KB_HEADER_B64}.${KB_PAYLOAD_B64}.${KB_SIGNATURE_B64}"

# 4. Constructing vp_token content (SD-JWT)
FULL_SD_JWT="${ISSUER_JWT}~${DISCLOSURE_1}~${DISCLOSURE_2}~${DISCLOSURE_3}~${DISCLOSURE_4}~${DISCLOSURE_5}~${KB_JWT}"

# 5. Structuring the vp_token container
VP_TOKEN_JSON=$(jq -n --arg cred "$FULL_SD_JWT" '{my_identity_credential: [$cred]}')

# 6. Mockup Wallet Instance Attestation (WIA)
WIA_HEADER_B64=$(echo -n '{"alg":"ES256","typ":"oauth-client-attestation+jwt"}' | base64 | tr -d '\r\n=' | tr '+/' '-_')
WIA_PAYLOAD_B64=$(echo -n "{\"iss\":\"https://wallet-provider-backend.eudi-wallet.de\",\"sub\":\"https://wallet.example.com/instances/12345\",\"wallet_name\":\"EUDI National Reference Wallet\",\"iat\":$(date +%s),\"exp\":$(( $(date +%s) + 3600 ))}" | base64 | tr -d '\r\n=' | tr '+/' '-_')
WIA_SIGNATURE_B64="simulated_wallet_manufacturer_signature"
MOCK_WIA_TOKEN="${WIA_HEADER_B64}.${WIA_PAYLOAD_B64}.${WIA_SIGNATURE_B64}"

echo -e "${COLOR_SUCCESS}✔ direct_post Datenstrukturen generiert!${COLOR_RESET}"

# -----------------------------------------------------------------------------
# STEP 4: direct_post callback
# -----------------------------------------------------------------------------
echo -e "\n${COLOR_INFO}[Step 4/4] Sending direct_post callback via HTTP POST...${COLOR_RESET}"

CALLBACK_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "state=$SESSION_ID" \
  --data-urlencode "vp_token=$VP_TOKEN_JSON" \
  --data-urlencode "wia_token=$MOCK_WIA_TOKEN" \
  "${API_BASE}/api/presentation/callback")

# Check if redirect_uri is present (indicating success state)
if echo "$CALLBACK_RESPONSE" | jq -e '.redirect_uri' > /dev/null; then
    REDIRECT_URI=$(echo "$CALLBACK_RESPONSE" | jq -r '.redirect_uri')
    echo -e "${COLOR_SUCCESS}✅ direct_post successful!${COLOR_RESET}"
    echo "  - redirect_uri: $REDIRECT_URI"
    
    # Querying onboarding status
    echo -e "\n${COLOR_INFO}Retrieving onboarding status from server...${COLOR_RESET}"
    STATUS_RESPONSE=$(curl -s "${API_BASE}/api/presentation/status?sid=${SESSION_ID}")
    echo -e "${COLOR_SUCCESS}--- SERVER STATUS REPLY ---${COLOR_RESET}"
    echo "$STATUS_RESPONSE" | jq '.'
    echo -e "${COLOR_SUCCESS}------------------------------${COLOR_RESET}"
    echo -e "\n${COLOR_SUCCESS}Success! Erika's identity claims have been processed.${COLOR_RESET}"
else
    echo -e "${COLOR_ERROR}❌ Error during callback execution; server reply:${COLOR_RESET}"
    echo "$CALLBACK_RESPONSE"
    exit 1
fi
