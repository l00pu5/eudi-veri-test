#!/usr/bin/env bash
# =============================================================================
# EUDI Wallet - Relying Party (RP) Test Harness & Integration Simulator (v2)
#
# This script automates the demonstration of a full cross-device presenation
# flow against the Express verification server.
# =============================================================================

set -euo pipefail

# confic options
API_BASE="http://localhost:3000"
COLOR_RESET="\033[0m"
COLOR_INFO="\033[34m"
COLOR_SUCCESS="\033[32m"
COLOR_WARN="\033[33m"
COLOR_ERROR="\033[31m"

echo -e "${COLOR_INFO}=== EUDI WALLET TEST HARNESS SIMULATOR (v2) ===${COLOR_RESET}"
echo "Checkingif Expredss server is up and running..."

# checking if Express server is up and running
if ! curl -s --head --request GET "${API_BASE}/api/presentation/initiate" > /dev/null; then
    echo -e "${COLOR_ERROR}Error: Express server at ${API_BASE} is not reachable!${COLOR_RESET}"
    echo "Please start the server via: node eudi-verifier-server-v4.js"
    exit 1
fi

# checking f jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${COLOR_ERROR}Error: 'jq' is not installed. Please ensure that it's installed in order to use this script.${COLOR_RESET}"
    exit 1
fi

# -----------------------------------------------------------------------------\n# SCHRITT 1: SESSION INITIALIZATION\n# -----------------------------------------------------------------------------
echo -e "\n${COLOR_INFO}[Step 1/4] Initiating new presentation session on the server...${COLOR_RESET}"
INIT_RESPONSE=$(curl -s "${API_BASE}/api/presentation/initiate")

# extraction of parameters
SESSION_ID=$(echo "$INIT_RESPONSE" | jq -r '.sessionId')
QR_CODE_URL=$(echo "$INIT_RESPONSE" | jq -r '.qrCodeUrl')

echo -e "${COLOR_SUCCESS}✔ Session has been initiated successfully!${COLOR_RESET}"
echo "  - Session ID (state): $SESSION_ID"
echo "  - QR code data:       $QR_CODE_URL"

# -----------------------------------------------------------------------------\n# SCHRITT 2: GATHER REQUEST OBJECT METADATA (JAR)\n# -----------------------------------------------------------------------------
echo -e "\n${COLOR_INFO}[Step 2/4] Simulating wallet: retrieving request object (JAR) via request_uri...${COLOR_RESET}"
# parsing request_uri from the openid4vp URI
REQUEST_URI=$(echo "$QR_CODE_URL" | grep -o 'request_uri=[^&]*' | cut -d'=' -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")

# retrieving signed request JWT
SIGNED_JAR=$(curl -s "$REQUEST_URI")

# decoding JWT payload to get the verifier's nonce
NONCE=$(python3 -c "
import sys, base64, json
try:
    jwt = sys.stdin.read().strip()
    parts = jwt.split('.')
    if len(parts) >= 2:
        p = parts[1]
        p += '=' * ((4 - len(p) % 4) % 4)
        print(json.loads(base64.urlsafe_b64decode(p).decode('utf-8')).get('nonce', ''))
    else:
        print('')
except Exception:
    print('')
" <<< "$SIGNED_JAR")

echo -e "${COLOR_SUCCESS}✔ Request Object (JAR) has been sucessfully retrieved and decoded!${COLOR_RESET}"
echo "  - Extracted transaction none: $NONCE"

# -----------------------------------------------------------------------------\n# SCHRITT 3: GENERATE HOLDER BINDING PROOF (MOCK)\n# -----------------------------------------------------------------------------
echo -e "\n${COLOR_INFO}[Step 3/4] Preparing Erika Mustermann tamper-proof direct_post payload...${COLOR_RESET}"

# 1. Issuer-signed JWT (header & payload with claims hashes)
ISSUER_HEADER_B64=$(echo -n '{"alg":"ES256","typ":"dc+sd-jwt"}' | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
ISSUER_PAYLOAD_B64=$(echo -n "{\"iss\":\"https://registry.government.de/pid-issuer\",\"iat\":$(date +%s),\"exp\":$(( $(date +%s) + 3600 )),\"vct\":\"https://credentials.example.com/identity_credential\",\"_sd_alg\":\"sha-256\",\"_sd\":[\"jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4\",\"TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo\"],\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\",\"y\":\"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"}}}" | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
ISSUER_SIGNATURE_B64="simulated_government_issuer_signature"
ISSUER_JWT="${ISSUER_HEADER_B64}.${ISSUER_PAYLOAD_B64}.${ISSUER_SIGNATURE_B64}"

# 2. Disclosures (clear texr values & salts)
# Disclosure 1: given_name -> ["salt123", "given_name", "Erika"]
DISCLOSURE_1=$(echo -n '["2GLC42sKQveCfGfryNRN9w", "given_name", "Erika"]' | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
# Disclosure 2: family_name -> ["salt456", "family_name", "Mustermann"]
DISCLOSURE_2=$(echo -n '["eluV5Og3gSNII8EYnsxA_A", "family_name", "Mustermann"]' | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
# Disclosure 3: birthdate -> ["salt789", "birthdate", "1998-08-12"]
DISCLOSURE_3=$(echo -n '["6Ij7tM-a5iVPGboS5tmvVA", "birthdate", "1998-08-12"]' | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
# Disclosure 4: is_over_18 -> ["saltabc", "is_over_18", true]
DISCLOSURE_4=$(echo -n '["Pc33JM2LchcU_lHggv_ufQ", "is_over_18", true]' | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
# Disclosure 5: address -> ["saltdef", "address", {...}]
DISCLOSURE_5=$(echo -n '["Qg_O64zqAxe412a108iroA", "address", {"street_address": "Heidestraße 17", "locality": "Köln", "postal_code": "50667", "country": "DE"}]' | base64 | tr -d '\r\n=' | tr -- '+/' '-_')

# 3. Key binding JWT (Holder Binding Proof, signed with device key)
KB_HEADER_B64=$(echo -n '{"alg":"ES256","typ":"kb+jwt"}' | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
KB_PAYLOAD_B64=$(echo -n "{\"nonce\":\"$NONCE\",\"aud\":\"x509_san_dns:client.example.org\",\"iat\":$(date +%s),\"sd_hash\":\"Dy-RYwZfaaoC3inJbLslgPvMp09bH-clYP_3qbRqtW4\"}" | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
KB_SIGNATURE_B64="simulated_device_secure_element_signature"
KB_JWT="${KB_HEADER_B64}.${KB_PAYLOAD_B64}.${KB_SIGNATURE_B64}"

# 4. Assembling final vp_token as SD-JWT VC
FULL_SD_JWT="${ISSUER_JWT}~${DISCLOSURE_1}~${DISCLOSURE_2}~${DISCLOSURE_3}~${DISCLOSURE_4}~${DISCLOSURE_5}~${KB_JWT}"

# 5. Structuring vp_token container
VP_TOKEN_JSON=$(jq -n --arg cred "$FULL_SD_JWT" '{my_identity_credential: [$cred]}')

# 6. Mockup Wallet Instance Attestation (WIA)
WIA_HEADER_B64=$(echo -n '{"alg":"ES256","typ":"oauth-client-attestation+jwt"}' | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
WIA_PAYLOAD_B64=$(echo -n "{\"iss\":\"https://wallet-provider-backend.eudi-wallet.de\",\"sub\":\"https://wallet.example.com/instances/12345\",\"wallet_name\":\"EUDI National Reference Wallet\",\"iat\":$(date +%s),\"exp\":$(( $(date +%s) + 3600 ))}" | base64 | tr -d '\r\n=' | tr -- '+/' '-_')
WIA_SIGNATURE_B64="simulated_wallet_manufacturer_signature"
MOCK_WIA_TOKEN="${WIA_HEADER_B64}.${WIA_PAYLOAD_B64}.${WIA_SIGNATURE_B64}"

echo -e "${COLOR_SUCCESS}✔ direct_post Datenstrukturen generiert!${COLOR_RESET}"

# -----------------------------------------------------------------------------\n# SCHRITT 4: EXECUTE DIRECT_POST CALLBACK\n# -----------------------------------------------------------------------------
echo -e "\n${COLOR_INFO}[Step 4/4] Sending direct_post callback via HTTP POST to server...${COLOR_RESET}"

CALLBACK_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "state=$SESSION_ID" \
  --data-urlencode "vp_token=$VP_TOKEN_JSON" \
  --data-urlencode "wia_token=$MOCK_WIA_TOKEN" \
  "${API_BASE}/api/presentation/callback")

# Checking if redirect_uri is delivered (indicating success)
if echo "$CALLBACK_RESPONSE" | jq -e '.redirect_uri' > /dev/null; then
    REDIRECT_URI=$(echo "$CALLBACK_RESPONSE" | jq -r '.redirect_uri')
    echo -e "${COLOR_SUCCESS}✅ direct_post completed successfully!${COLOR_RESET}"
    echo "  - Received Redirect URI: $REDIRECT_URI"
    
    # querying onboarding status
    echo -e "\n${COLOR_INFO}Querying onboarding status from server...${COLOR_RESET}"
    STATUS_RESPONSE=$(curl -s "${API_BASE}/api/presentation/status?sid=${SESSION_ID}")
    echo -e "${COLOR_SUCCESS}--- SERVER STATUS REPLY ---${COLOR_RESET}"
    echo "$STATUS_RESPONSE" | jq '.'
    echo -e "${COLOR_SUCCESS}------------------------------${COLOR_RESET}"
    echo -e "\n${COLOR_SUCCESS}Congratulations! Erika Mustermann identity has been processed successfully.${COLOR_RESET}"
else
    echo -e "${COLOR_ERROR}❌ Error during callback! Server reply:${COLOR_RESET}"
    echo "$CALLBACK_RESPONSE"
    exit 1
fi
