/**
 * EUDI Wallet OpenID4VCI Validator
 * 
 * Validates Credential Offers (Deeplinks / URIs), issuer metadata,
 * OAuth2 discovery endpoints + encryption declaration
 *
 * Usage:
 *   node eudi-issuance-validator.js "<>"
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

// ANSI Color Codes für strukturierte Konsolenausgabe
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m"
};

const logHeader = (msg) => console.log(`\n${colors.bright}${colors.cyan}--- ${msg} ---${colors.reset}`);
const logSuccess = (msg) => console.log(`  ${colors.green}✓ ${msg}${colors.reset}`);
const logWarn = (msg) => console.log(`  ${colors.yellow}⚠️  ${msg}${colors.reset}`);
const logError = (msg) => console.log(`  ${colors.red}❌ ${msg}${colors.reset}`);
const logInfo = (msg) => console.log(`  ${colors.blue}ℹ ${msg}${colors.reset}`);

// collecting validation results
const results = {
  errors: [],
  warnings: [],
  info: []
};

// aux function for HTTP/HTTPS GET requests
function fetchUrl(targetUrl) {
  return new Promise((resolve, reject) => {
    try {
      const parsedUrl = new URL(targetUrl);
      const client = parsedUrl.protocol === 'https:' ? https : http;

      const req = client.get(targetUrl, {
        headers: { 'Accept': 'application/json, application/jwt' }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ statusCode: res.statusCode, data, headers: res.headers });
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          }
        });
      });

      req.on('error', (err) => reject(err));
      req.setTimeout(8000, () => {
        req.destroy();
        reject(new Error('Timeout while fetching URL'));
      });
    } catch (e) {
      reject(e);
    }
  });
}

// helper: parse Base64URL JWT payload
function parseJwtPayload(jwtString) {
  try {
    const parts = jwtString.split('.');
    if (parts.length !== 3) return null;
    const payloadBase64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const jsonStr = Buffer.from(payloadBase64, 'base64').toString('utf-8');
    return JSON.parse(jsonStr);
  } catch (e) {
    return null;
  }
}

// validation logic
async function validateIssuanceInput(rawInput) {
  console.log(`\n${colors.bright}${colors.cyan}=================================================================${colors.reset}`);
  console.log(`${colors.bright}${colors.cyan}   EUDI WALLET ISSUANCE VALIDATION TOOL             ${colors.reset}`);
  console.log(`${colors.bright}${colors.cyan}=================================================================${colors.reset}\n`);

  let credentialOfferObj = null;
  let issuerUrl = null;

  // input parsing (deeplink / JSON / URL)
  logHeader('1. ANALYSIS OF INPUT & CREDENTIAL OFFER');

  if (!rawInput || typeof rawInput !== 'string') {
    logError('No input');
    results.errors.push('Invalid input');
    return printSummary();
  }

  const trimmed = rawInput.trim();

  if (trimmed.startsWith('openid-credential-offer://') || trimmed.startsWith('https://') || trimmed.startsWith('http://')) {
    try {
      const parsedUrl = new URL(trimmed);
      if (parsedUrl.protocol === 'openid-credential-offer:') {
        results.info.push("Input recognized as 'openid-credential-offer://' deeplink");
        logSuccess("Deeplink schema correct: 'openid-credential-offer://'");

        const offerParam = parsedUrl.searchParams.get('credential_offer');
        const offerUriParam = parsedUrl.searchParams.get('credential_offer_uri');

        if (offerParam) {
          try {
            credentialOfferObj = JSON.parse(offerParam);
            results.info.push("Credential offer has been successfully parsed from query parameter");
            logSuccess("Query parameter 'credential_offer' is valid (JSON)");
          } catch (e) {
            logError("Query parameter 'credential_offer' is not valid JSON");
            results.errors.push("Error while parsing 'credential_offer' as JSON");
          }
        } else if (offerUriParam) {
          logInfo(`Remote offer via 'credential_offer_uri': ${offerUriParam}`);
          try {
            const res = await fetchUrl(offerUriParam);
            credentialOfferObj = JSON.parse(res.data);
            results.info.push("Credential offer loaded successfully from 'credential_offer_uri'");
            logSuccess("Remote credential offer loaded successfully");
          } catch (err) {
            logError(`Error while fetching from 'credential_offer_uri': ${err.message}`);
            results.errors.push(`credential_offer_uri not reachable: ${err.message}`);
          }
        } else {
          logError("Deeplink does not contain 'credential_offer' or 'credential_offer_uri'");
          results.errors.push("Missing offer parameters from deeplink");
        }
      } else {
        // direct HTTP/HTTPS URL -> treat as issuer base URL or direct offer
        logInfo(`Input detected as web URL: ${trimmed}`);
        if (trimmed.includes('.well-known/openid-credential-issuer')) {
          issuerUrl = trimmed.split('/.well-known/')[0];
        } else {
          issuerUrl = trimmed;
        }
      }
    } catch (e) {
      logError(`Error while parsing the URL: ${e.message}`);
      results.errors.push("Invalid URL format");
    }
  } else if (trimmed.startsWith('{')) {
    try {
      credentialOfferObj = JSON.parse(trimmed);
      results.info.push("Input of JSON object (Credential Offer) detected");
      logSuccess("Direct JSON input is valid JSON");
    } catch (e) {
      logError("Input is not well-formatted JSON");
      results.errors.push("Invalid JSON format");
    }
  } else {
    logError("Unknown input fornat; expected: openid-credential-offer:// deeplink, HTTP URL or JSON");
    results.errors.push("Unknwon / invalid input format");
    return printSummary();
  }

  // check credential offer structure
  if (credentialOfferObj) {
    logHeader('2. STRUCTURAL CHECK: CREDENTIAL OFFER OBJECT');

    // credential_issuer check
    if (credentialOfferObj.credential_issuer && typeof credentialOfferObj.credential_issuer === 'string') {
      issuerUrl = credentialOfferObj.credential_issuer;
      logSuccess(`credential_issuer found: ${issuerUrl}`);
      results.info.push(`credential_issuer: ${issuerUrl}`);

      if (!issuerUrl.startsWith('https://') && !issuerUrl.startsWith('http://localhost')) {
        logWarn("credential_issuer is not using HTTPS ");
        results.warnings.push("credential_issuer is not using HTTPS");
      }
    } else {
      logError("Mandatory field 'credential_issuer' is missing from credential offer");
      results.errors.push("Missing required field: credential_issuer");
    }

    // credential_configuration_ids check
    if (Array.isArray(credentialOfferObj.credential_configuration_ids) && credentialOfferObj.credential_configuration_ids.length > 0) {
      logSuccess(`credential_configuration_ids: [${credentialOfferObj.credential_configuration_ids.map(c => `'${c}'`).join(', ')}]`);
      results.info.push(`Active config IDs: ${credentialOfferObj.credential_configuration_ids.length}`);
    } else {
      logError("Mandatory field 'credential_configuration_ids' is missing or array is empty");
      results.errors.push("Missing or empty field: credential_configuration_ids");
    }

    // grants check
    if (credentialOfferObj.grants && typeof credentialOfferObj.grants === 'object') {
      logSuccess("grants object found");

      const authCodeGrant = credentialOfferObj.grants['authorization_code'];
      const preAuthGrant = credentialOfferObj.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];

      if (authCodeGrant) {
        logInfo("Grant type: Authorization Code Flow");
        if (authCodeGrant.issuer_state) {
          logSuccess(`issuer_state found: ${authCodeGrant.issuer_state}`);
        }
      }
      if (preAuthGrant) {
        logInfo("Grant type: Pre-Authorized Code Flow");
        if (preAuthGrant['pre-authorized_code']) {
          logSuccess(`pre-authorized_code found (${preAuthGrant['pre-authorized_code'].substring(0, 10)}...)`);
        } else {
          logError("Pre-Authorized Code Grant declared, but field 'pre-authorized_code' is missing");
          results.errors.push("Missing pre-authorized_code in grants.");
        }
        if (preAuthGrant.user_pin_required !== undefined) {
          logInfo(`user_pin_required (legacy): ${preAuthGrant.user_pin_required}`);
        }
        if (preAuthGrant.tx_code) {
          logSuccess(`tx_code specification found (input type: ${preAuthGrant.tx_code.input_mode || 'numeric'}, length: ${preAuthGrant.tx_code.length || 'default'})`);
        }
      }

      if (!authCodeGrant && !preAuthGrant) {
        logWarn("grants object does not contain 'authorization_code' or 'pre-authorized_code'");
        results.warnings.push("No known grant type defined in grants");
      }
    } else {
      logWarn("No 'grants' object defined in credential offer");
      results.warnings.push("Optional 'grants' object is missing");
    }
  }

  // issuer metadata verification (GET /.well-known/openid-credential-issuer)
  if (issuerUrl) {
    logHeader('3. ISSUER METADATA VERIFICATION (/.well-known/openid-credential-issuer)');
    const metadataUrl = `${issuerUrl.replace(/\/$/, '')}/.well-known/openid-credential-issuer`;
    logInfo(`Retrieving issuer netadata: ${metadataUrl}`);

    let metadataObj = null;

    try {
      const res = await fetchUrl(metadataUrl);
      logSuccess(`Metadata endpoint is reachable (HTTP ${res.statusCode}).`);

      if (res.headers['content-type'] && res.headers['content-type'].includes('application/jwt')) {
        logInfo("Metadata received as signed JWT (signed_metadata)");
        metadataObj = parseJwtPayload(res.data);
        if (metadataObj) {
          logSuccess("signed_metadata JWT Payload parsed successfully");
        } else {
          logError("signed_metadata JWT could not be decoded");
          results.errors.push("invalid signed_metadata JWT");
        }
      } else {
        metadataObj = JSON.parse(res.data);
        logSuccess("Metadata received as JSON");
      }
    } catch (err) {
      logError(`Error while retrieving issuer metadata: ${err.message}`);
      results.errors.push(`Issuer metadata not reachable: ${err.message}`);
    }

    if (metadataObj) {
      // Check issuer url match
      if (metadataObj.credential_issuer) {
        logSuccess(`credential_issuer in metadata: ${metadataObj.credential_issuer}`);
      } else {
        logError("Mandatory field 'credential_issuer' missing from metadata!");
        results.errors.push("Missing credential_issuer in metadata.");
      }

      if (metadataObj.credential_endpoint) {
        logSuccess(`credential_endpoint: ${metadataObj.credential_endpoint}`);
      } else {
        logError("Mandatory field 'credential_endpoint' missing from metadata");
        results.errors.push("Missing credential_endpoint in metadata.");
      }

      if (metadataObj.nonce_endpoint) {
        logSuccess(`nonce_endpoint: ${metadataObj.nonce_endpoint}`);
      } else {
        logWarn("Optional 'nonce_endpoint' not defined in metadata");
      }

      // encryption metadata checks
      logHeader('4. ENCRYPTION METADATA & JWKS VALIDATION');

      // response encryption
      if (metadataObj.credential_response_encryption) {
        const respEnc = metadataObj.credential_response_encryption;
        logSuccess("credential_response_encryption defined");

        if (Array.isArray(respEnc.alg_values_supported) && respEnc.alg_values_supported.length > 0) {
          logSuccess(`Response encryption alg_values: [${respEnc.alg_values_supported.join(', ')}]`);
        } else {
          logError("credential_response_encryption: 'alg_values_supported' is missing or empty");
          results.errors.push("Missing alg_values_supported in credential_response_encryption.");
        }

        if (Array.isArray(respEnc.enc_values_supported) && respEnc.enc_values_supported.length > 0) {
          logSuccess(`Response encryption enc_values: [${respEnc.enc_values_supported.join(', ')}]`);
        } else {
          logError("credential_response_encryption: 'enc_values_supported' is missing or empty");
          results.errors.push("Missing enc_values_supported in credential_response_encryption.");
        }
      } else {
        logWarn("No 'credential_response_encryption' declared on root level of metadata");
        results.warnings.push("credential_response_encryption not declared on root level");
      }

      // request encryption
      if (metadataObj.credential_request_encryption) {
        const reqEnc = metadataObj.credential_request_encryption;
        logSuccess("credential_request_encryption defined");

        if (reqEnc.jwks && Array.isArray(reqEnc.jwks.keys) && reqEnc.jwks.keys.length > 0) {
          logSuccess(`credential_request_encryption.jwks contains ${reqEnc.jwks.keys.length} keys`);

          reqEnc.jwks.keys.forEach((key, idx) => {
            logInfo(`Checking JWK [${idx}] for credential request encryption...`);

            if (!key.kty) {
              logError(`JWK [${idx}]: mandatory field 'kty' is missing`);
              results.errors.push(`JWK[${idx}] missing kty`);
            }
            if (!key.kid) {
              logError(`JWK [${idx}]: mandatory field 'kid' is missing`);
              results.errors.push(`JWK[${idx}] missing kid`);
            } else {
              logSuccess(`JWK [${idx}]: kid = '${key.kid}'`);
            }

            if (!key.alg) {
              logError(`JWK [${idx}]: mandatory field 'alg' is missing`);
              results.errors.push(`JWK[${idx}] missing alg`);
            } else {
              logSuccess(`JWK [${idx}]: alg = '${key.alg}'`);
            }

            if (key.use !== 'enc') {
              logError(`JWK [${idx}]: 'use' must be 'enc'; actual: '${key.use}'`);
              results.errors.push(`JWK[${idx}] use is not 'enc'`);
            } else {
              logSuccess(`JWK [${idx}]: use = 'enc' (correct)`);
            }
          });
        } else {
          logError("credential_request_encryption is declared, but 'jwks.keys' is missing or empty");
          results.errors.push("Missing jwks in credential_request_encryption.");
        }
      } else if (metadataObj.credential_response_encryption) {
        logError("credential_response_encryption is declared, but credential_request_encryption is missing");
        results.errors.push("Missing credential_request_encryption when credential_response_encryption is specified.");
      }

      // credential configurations supported
      logHeader('5. CREDENTIAL CONFIGURATIONS SUPPORTED');

      const configs = metadataObj.credential_configurations_supported;
      if (configs && typeof configs === 'object' && Object.keys(configs).length > 0) {
        logSuccess(`Count of supported credental configurations: ${Object.keys(configs).length}`);

        // if a credential offer exists: check if offered IDs are existing at the issuer
        if (credentialOfferObj && Array.isArray(credentialOfferObj.credential_configuration_ids)) {
          credentialOfferObj.credential_configuration_ids.forEach(offerId => {
            if (configs[offerId]) {
              logSuccess(`Offered config ID '${offerId}' foud in issuer metadata`);
              const conf = configs[offerId];
              logInfo(`  Format: ${conf.format || 'N/A'}, Scope/VCT: ${conf.scope || conf.vct || conf.doctype || 'N/A'}`);

              // Proof types
              if (conf.proof_types_supported && conf.proof_types_supported.jwt) {
                logSuccess(`  proof_types_supported.jwt defined (algs: [${(conf.proof_types_supported.jwt.proof_signing_alg_values_supported || []).join(', ')}])`);
              } else {
                logWarn(`  proof_types_supported.jwt for '${offerId}' is missing or incomplete`);
              }
            } else {
              logError(`Offered config ID '${offerId}' not found credential_configurations_supported`);
              results.errors.push(`Offered config ID '${offerId}' missing in issuer metadata.`);
            }
          });
        }
      } else {
        logError("Mandatory object 'credential_configurations_supported' is missing or empty");
        results.errors.push("Missing credential_configurations_supported in metadata.");
      }
    }
  }

  printSummary();
}

function printSummary() {
  console.log(`\n${colors.bright}${colors.cyan}=================================================================${colors.reset}`);
  console.log(`${colors.bright}${colors.cyan}                     VALIDATION RESULTS                         ${colors.reset}`);
  console.log(`${colors.bright}${colors.cyan}=================================================================${colors.reset}\n`);

  if (results.info.length > 0) {
    console.log(`${colors.bright}[INFO / DETAILS]:${colors.reset}`);
    results.info.forEach(i => console.log(`  ✓ ${i}`));
    console.log('');
  }

  if (results.warnings.length > 0) {
    console.log(`${colors.bright}${colors.yellow}[WARNINGS]:${colors.reset}`);
    results.warnings.forEach(w => console.log(`  ⚠️  ${w}`));
    console.log('');
  }

  if (results.errors.length > 0) {
    console.log(`${colors.bright}${colors.red}[ERRORS]:${colors.reset}`);
    results.errors.forEach(e => console.log(`  ❌ ${e}`));
    console.log('');
  }

  console.log(`-----------------------------------------------------------------`);
  if (results.errors.length === 0) {
    console.log(`${colors.bright}${colors.green}STATUS: ✅ VALID${colors.reset}`);
  } else {
    console.log(`${colors.bright}${colors.red}STATUS: ❌ INVALID ${colors.reset}`);
  }
  console.log(`-----------------------------------------------------------------\n`);
}

// CLI Execution
const args = process.argv.slice(2);
if (args.length === 0) {
  console.log(`Usage: node eudi-issuance-validator.js "<>"`);
  process.exit(1);
}

validateIssuanceInput(args[0]).catch(err => {
  console.error("Unexpected error during validation:", err);
});
