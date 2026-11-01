/**
 * EUDI Wallet OpenID4VP Validator
 * 
 * Validates OpenID4VP deeplinks (openid4vp://) and JAR request JWTs (RFC 9101 / HAIP 1.0).
 * Usage: node eudi-presentation-validator.js "<>"
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');
const { Logger } = require("./util/logger.js");

// aux function for base64url decoding
function decodeBase64Url(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

// aux function for fetching URLs
function fetchUrl(targetUrl) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(targetUrl);
    const client = parsedUrl.protocol === 'https:' ? https : http;

    const options = {
      headers: {
        'Accept': 'application/oauth-authz-req+jwt, application/jwt, */*'
      }
    };

    client.get(targetUrl, options, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return reject(new Error(`HTTP-Fehler ${res.statusCode}: ${res.statusMessage}`));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ body: data, headers: res.headers, statusCode: res.statusCode }));
    }).on('error', reject);
  });
}

class OpenID4VPRequestValidator {
  constructor() {
    this.report = {
      valid: true,
      errors: [],
      warnings: [],
      info: [],
      summary: {}
    };
  }

  logError(msg) {
    this.report.valid = false;
    this.report.errors.push(msg);
  }

  logWarning(msg) {
    this.report.warnings.push(msg);
  }

  logInfo(msg) {
    this.report.info.push(msg);
  }

  async validateInput(inputStr) {
    console.log("\n=================================================================");
    console.log("   EUDI REQUEST OBJECT VALIDATION TOOL   ");
    console.log("=================================================================\n");

    let requestJwt = '';
    let urlParamsClientId = null;

    inputStr = inputStr.trim();

    // 1. distinction of input link (deeplink vs. URL vs. raw JWT)
    if (inputStr.startsWith('openid4vp://') || inputStr.startsWith('openid://')) {
      this.logInfo(`OpenID4VP deeplink detected: ${inputStr}`);
      try {
        const urlObj = new URL(inputStr.replace('openid4vp://', 'https://dummy/').replace('openid://', 'https://dummy/'));
        const requestUri = urlObj.searchParams.get('request_uri');
        urlParamsClientId = urlObj.searchParams.get('client_id');

        if (!requestUri) {
          this.logError("Deeplink does not contain 'request_uri' parameter");
          return this.printReport();
        }

        this.logInfo(`Obtaining request JWT from request_uri: ${requestUri}`);
        const res = await fetchUrl(requestUri);
        requestJwt = res.body.trim();
        this.logInfo(`Request JWT obtained successfully (HTTP ${res.statusCode}, Content-Type: ${res.headers['content-type'] || 'n/a'}).`);
      } catch (err) {
        this.logError(`Error while fetching request_uri: ${err.message}`);
        return this.printReport();
      }
    } else if (inputStr.startsWith('http://') || inputStr.startsWith('https://')) {
      this.logInfo(`HTTP/HTTPS URL (request_uri) detected: ${inputStr}`);
      try {
        const res = await fetchUrl(inputStr);
        requestJwt = res.body.trim();
        this.logInfo(`Request JWT obtained successfully (HTTP ${res.statusCode}).`);
      } catch (err) {
        this.logError(`Error while fetching the URL: ${err.message}`);
        return this.printReport();
      }
    } else if (inputStr.split('.').length === 3) {
      this.logInfo("JWT detected");
      requestJwt = inputStr;
    } else {
      this.logError("Input is neither deeplink, URL nor JWT");
      return this.printReport();
    }

    // 2. JWT parser & header check
    const parts = requestJwt.split('.');
    if (parts.length !== 3) {
      this.logError(`Invalid JWT format, 3 segments (Header.Payload.Sig) were expected, ${parts.length} segments received instead`);
      return this.printReport();
    }

    let header, payload;
    try {
      header = JSON.parse(decodeBase64Url(parts[0]));
      this.logInfo("JWS header parsed successfully");
    } catch (e) {
      this.logError(`Error while decoding the JWS header: ${e.message}`);
      return this.printReport();
    }

    try {
      payload = JSON.parse(decodeBase64Url(parts[1]));
      this.logInfo("JAR payload (authorization request object) parsed successfully");
    } catch (e) {
      this.logError(`Error while decoding the JAR payload: ${e.message}`);
      return this.printReport();
    }

    this.validateJwsHeader(header);
    this.validatePayload(payload, urlParamsClientId);

    return this.printReport(header, payload);
  }

  validateJwsHeader(header) {
    console.log("--- 1. CHECKING THE JWS HEADER (JOSE HEADER) ---");

    // Algorithmus
    if (!header.alg) {
      this.logError("JWS header is missing mandatory field 'alg'");
    } else {
      this.logInfo(`Signature algorithm (alg): ${header.alg}`);
      if (!['ES256', 'ES384', 'ES512', 'RS256', 'PS256', 'EdDSA'].includes(header.alg)) {
        this.logWarning(`Unexpected or unsafe signature algorithm was detected: ${header.alg}`);
      }
    }

    // Typ (HAIP / RFC 9101)
    if (!header.typ) {
      this.logWarning("JWS header is missing mandatory field 'typ' (recommended: 'oauth-authz-req+jwt')");
    } else {
      this.logInfo(`Header type (typ): ${header.typ}`);
      if (header.typ !== 'oauth-authz-req+jwt' && header.typ !== 'JWT') {
        this.logWarning(`Deviating 'typ' header: '${header.typ}'; recommended value for HAIP 1.0 = 'oauth-authz-req+jwt'`);
      }
    }

    // certificate chain (x5c) or JWK
    if (header.x5c) {
      if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
        this.logError("'x5c' header detected, but not a valid & non-empty array");
      } else {
        this.logInfo(`'x5c' certificate chain detected (${header.x5c.length} certs).`);
      }
    } else if (header.jwk) {
      this.logInfo("'jwk' key found in header");
    } else {
      this.logWarning("Neither 'x5c' nor 'jwk' found in JWS header; trust anchor verification depends on client_id scheme now");
    }
  }

  validatePayload(payload, urlParamsClientId) {
    console.log("--- 2. CHECKING THE AUTHORIZATION REQUEST OBJECT (PAYLOAD) ---");

    // client_id
    if (!payload.client_id) {
      this.logError("Mandatory field 'client_id' missing from request object payload");
    } else {
      this.logInfo(`client_id: ${payload.client_id}`);
      if (urlParamsClientId && urlParamsClientId !== payload.client_id) {
        this.logError(`Mismatch between deeplink client_id ('${urlParamsClientId}') and payload client_id ('${payload.client_id}')`);
      }
    }

    // response_type
    if (!payload.response_type) {
      this.logError("Mandatory field 'response_type' missing from request object payload");
    } else if (payload.response_type !== 'vp_token') {
      this.logError(`Invalid 'response_type': '${payload.response_type}'; expected: 'vp_token'.`);
    } else {
      this.logInfo("response_type: 'vp_token' (correct)");
    }

    // response_mode
    if (!payload.response_mode) {
      this.logError("Mandatory field 'response_mode' missing from request obect payload");
    } else {
      this.logInfo(`response_mode: ${payload.response_mode}`);
      if (!['direct_post', 'direct_post.jwt'].includes(payload.response_mode)) {
        this.logWarning(`Unexpected response_mode found: '${payload.response_mode}'.`);
      }
      if (payload.response_mode === 'direct_post') {
        this.logWarning("response_mode = 'direct_post' (unencrypted); 'direct_post.jwt' expected for HAIP compliancy");
      }
    }

    // response_uri vs redirect_uri
    if (!payload.response_uri) {
      this.logError("Mandatory field 'response_uri' missing for direct_post / direct_post.jwt.");
    } else {
      this.logInfo(`response_uri: ${payload.response_uri}`);
      if (!payload.response_uri.startsWith('https://')) {
        this.logError(`'response_uri' is required to be a secured HTTPS URL: '${payload.response_uri}'`);
      }
    }

    if (payload.redirect_uri) {
      this.logError(`Invalid combination: 'redirect_uri' MUST NOT be provided for 'response_mode=${payload.response_mode}'`);
    }

    // nonce
    if (!payload.nonce) {
      this.logError("Mandatory field 'nonce' missing from request object payload");
    } else {
      this.logInfo(`nonce: ${payload.nonce}`);
      if (payload.nonce.length < 16) {
        this.logWarning(`Insufficient entropy of 'nonce': length is ${payload.nonce.length} chars (recommended: 16-32)`);
      }
    }

    // state
    if (!payload.state) {
      this.logWarning("Field 'state' missing; is recommanded für replay attack protection");
    } else {
      this.logInfo(`state: ${payload.state}`);
    }

    // client_metadata & encryption keys (for direct_post.jwt)
    this.validateClientMetadata(payload);

    // DCQL query or presentation definition
    this.validateQueries(payload);
  }

  validateClientMetadata(payload) {
    console.log("--- 3. CHECKING CLIENT_METADATA & ENCRYPTION ---");
    const meta = payload.client_metadata;

    if (!meta) {
      if (payload.response_mode === 'direct_post.jwt') {
        this.logError("'client_metadata' missing, but is required for 'direct_post.jwt' (JWKS for encryption)");
      } else {
        this.logWarning("'client_metadata' missing fro request object");
      }
      return;
    }

    // JWE encryption key (for direct_post.jwt)
    if (payload.response_mode === 'direct_post.jwt') {
      if (!meta.jwks || !Array.isArray(meta.jwks.keys) || meta.jwks.keys.length === 0) {
        this.logError("'client_metadata.jwks.keys' is missing or empty (wallet will be unable to encrypt the JWE response)");
      } else {
        this.logInfo(`Count of ephemeral encryption keys in JWKS: ${meta.jwks.keys.length}`);
        meta.jwks.keys.forEach((key, index) => {
          this.validateEncryptionJwk(key, index);
        });
      }

      if (!meta.encrypted_response_enc_values_supported) {
        this.logWarning("'client_metadata.encrypted_response_enc_values_supported' missing (default: A128GCM / A256GCM)");
      } else {
        this.logInfo(`Supported content encryption algorithms: ${JSON.stringify(meta.encrypted_response_enc_values_supported)}`);
      }
    }

    // supported VP formats
    if (meta.vp_formats_supported) {
      this.logInfo(`Declared VP formats: ${Object.keys(meta.vp_formats_supported).join(', ')}`);
    }
  }

  validateEncryptionJwk(key, index) {
    const prefix = `JWK[${index}]`;
    if (!key.kty) this.logError(`${prefix}: Mandatory field 'kty' is missing`);
    if (!key.crv) this.logError(`${prefix}: Mandatory field 'crv' (e.g. P-256) is missing`);
    if (!key.x || !key.y) this.logError(`${prefix}: Public occordinates 'x' or 'y' are missing`);

    // EUDI Android Wallet SDK-specific fields
    if (!key.kid) {
      this.logError(`${prefix}: Mandatory field 'kid' (key ID) is missing`);
    } else {
      this.logInfo(`${prefix}: kid = '${key.kid}'`);
    }

    if (!key.alg) {
      this.logError(`${prefix}: Mandatory field 'alg' (e.g. 'ECDH-ES') is missing`);
    } else {
      this.logInfo(`${prefix}: alg = '${key.alg}'`);
    }

    if (key.use !== 'enc') {
      this.logError(`${prefix}: Field 'use' must have value 'enc'; actual: '${key.use}'`);
    } else {
      this.logInfo(`${prefix}: use = 'enc' (correct)`);
    }
  }

  validateQueries(payload) {
    console.log("--- 4. CHECK OF CREDENTIAL REQUEST (DCQL / PRESENTATION DEFINITION) ---");

    if (payload.dcql_query) {
      this.logInfo("Request is using DCQL");
      const dcql = payload.dcql_query;

      if (!dcql.credentials || !Array.isArray(dcql.credentials) || dcql.credentials.length === 0) {
        this.logError("DCQL query 'credentials' array is missing or empty");
      } else {
        this.logInfo(`DCQL queries ${dcql.credentials.length} credential(s)`);
        dcql.credentials.forEach((cred, i) => {
          this.validateDcqlCredential(cred, i);
        });
      }
    } else if (payload.presentation_definition) {
      this.logInfo("Request is using W3C Presentation Definition (DIF)");
    } else {
      this.logError("Neither 'dcql_query' nor 'presentation_definition' found in request object");
    }
  }

  validateDcqlCredential(cred, i) {
    const prefix = `DCQL credential[${i}] (id: '${cred.id || 'n/a'}')`;
    if (!cred.id) this.logError(`${prefix}: Mandatory field 'id' is missing`);
    if (!cred.format) this.logError(`${prefix}: Mandatory field 'format' is missing`);

    this.logInfo(`${prefix}: Format = '${cred.format}'`);

    if (cred.format === 'mso_mdoc') {
      if (!cred.meta) {
        this.logError(`${prefix}: 'meta' object missing for mso_mdoc`);
      } else if (!cred.meta.doctype_value) {
        this.logError(`${prefix}: Mandatory field 'meta.doctype_value' is missing for mso_mdoc`);
      } else {
        this.logInfo(`${prefix}: meta.doctype_value = '${cred.meta.doctype_value}' (correct)`);
      }
    } else if (cred.format === 'dc+sd-jwt') {
      if (cred.meta && cred.meta.vct_values) {
        this.logInfo(`${prefix}: meta.vct_values = ${JSON.stringify(cred.meta.vct_values)}`);
      }
    }

    if (cred.claims && Array.isArray(cred.claims)) {
      this.logInfo(`${prefix}: ${cred.claims.length} claim(s) requested`);
      cred.claims.forEach((claim, cIdx) => {
        if (!claim.path || !Array.isArray(claim.path)) {
          this.logError(`${prefix} claim[${cIdx}]: 'path' has to be an array of strings`);
        }
      });
    }
  }

  printReport(header, payload) {
    console.log("=================================================================");
    console.log("                     RESULTS                                     ");
    console.log("=================================================================");

    if (this.report.info.length > 0) {
      console.log("[INFO / DETAILS]:");
      this.report.info.forEach(msg => console.log(`  ✓ ${msg}`));
    }

    if (this.report.warnings.length > 0) {
      console.log("[WARNINGS]:");
      this.report.warnings.forEach(msg => console.log(`  ⚠️  ${msg}`));
    }

    if (this.report.errors.length > 0) {
      console.log("[ERRORS]:");
      this.report.errors.forEach(msg => console.log(`  ❌ ${msg}`));
    }

    console.log("-----------------------------------------------------------------");
    if (this.report.valid) {
      console.log("STATUS: ✅ VALID");
    } else {
      console.log("STATUS: ❌ INVALID");
    }
    console.log("-----------------------------------------------------------------");

    return this.report;
  }
}

// CLI execution wrapper
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log("Usage: node eudi-presentation-validator.js \"<>\"");
    process.exit(1);
  }

  const validator = new OpenID4VPRequestValidator();
  validator.validateInput(args[0]).catch(err => {
    console.error("Unexpected error:", err);
  });
}

module.exports = OpenID4VPRequestValidator;
