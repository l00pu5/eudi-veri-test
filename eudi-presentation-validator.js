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
    console.log("   EUDI WALLET OPENID4VP REQUEST OBJECT VALIDATOR   ");
    console.log("=================================================================\n");

    let requestJwt = '';
    let urlParamsClientId = null;

    inputStr = inputStr.trim();

    // 1. distinction between input formats (deeplink vs URL vs raw JWT)
    if (inputStr.startsWith('openid4vp://') || inputStr.startsWith('openid://')) {
      this.logInfo(`OpenID4VP deeplink has been detected: ${inputStr}`);
      try {
        const urlObj = new URL(inputStr.replace('openid4vp://', 'https://dummy/').replace('openid://', 'https://dummy/'));
        const requestUri = urlObj.searchParams.get('request_uri');
        urlParamsClientId = urlObj.searchParams.get('client_id');

        if (!requestUri) {
          this.logError("Deeplink does not contain 'request_uri' parameter");
          return this.printReport();
        }

        this.logInfo(`Fetching request JWT from request_uri: ${requestUri}`);
        const res = await fetchUrl(requestUri);
        requestJwt = res.body.trim();
        this.logInfo(`Request JWT retrieved successfully (HTTP ${res.statusCode}, Content-Type: ${res.headers['content-type'] || 'n/a'}).`);

        // RFC 9101 one-time retrieval check (test for second retrieval)
        try {
          this.logInfo("Probing one-time retrieval (second fetch from request_uri)...");
          const res2 = await fetchUrl(requestUri);
          if (res2.statusCode === 200) {
            this.logWarning("⚠️ one-time retrieval check: server has delivered the request object again (HTTP 200)");
          }
        } catch (err2) {
          if (err2.message.includes('410') || err2.message.includes('400') || err2.message.includes('404')) {
            this.logInfo(`✓ one-time retrieval check successful: 2nd request was rejected (${err2.message}).`);
          } else {
            this.logInfo(`2nd request result: ${err2.message}`);
          }
        }
      } catch (err) {
        this.logError(`Error while fetching from request_uri: ${err.message}`);
        return this.printReport();
      }
    } else if (inputStr.startsWith('http://') || inputStr.startsWith('https://')) {
      this.logInfo(`HTTP/HTTPS URL (request_uri) detected: ${inputStr}`);
      try {
        const res = await fetchUrl(inputStr);
        requestJwt = res.body.trim();
        this.logInfo(`Request JWT retrieved successfully (HTTP ${res.statusCode}).`);

        // RFC 9101 one-time retrieval check (test for second retrieval)
        try {
          this.logInfo("Probing one-time retrieval (second fetch from request_uri)...");
          const res2 = await fetchUrl(inputStr);
          if (res2.statusCode === 200) {
            this.logWarning("⚠️ one-time retrieval check: server has delivered the request object again (HTTP 200)");
          }
        } catch (err2) {
          if (err2.message.includes('410') || err2.message.includes('400') || err2.message.includes('404')) {
            this.logInfo(`✓ one-time retrieval check successful: 2nd request was rejected (${err2.message}).`);
          } else {
            this.logInfo(`2nd request result: ${err2.message}`);
          }
        }
      } catch (err) {
        this.logError(`Error while fetching from URL: ${err.message}`);
        return this.printReport();
      }
    } else if (inputStr.split('.').length === 3) {
      this.logInfo("Input has been detected as 3-part JWT");
      requestJwt = inputStr;
    } else {
      this.logError("Input format could not be detected (not deeplink, URL or JWT)");
      return this.printReport();
    }

    // 2. JWT parser & header check
    const parts = requestJwt.split('.');
    if (parts.length !== 3) {
      this.logError(`Invalid JWT format: 3 segments (Header.Payload.Sig) expected, detected ${parts.length} segment(s) instead`);
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
      this.logInfo("JAR payload (Authorization Request Object) has been parsed successfully");
    } catch (e) {
      this.logError(`Error while decoding the JWT payload: ${e.message}`);
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
      this.logError("Mandatory field 'alg' missing from JWS header");
    } else {
      this.logInfo(`Signature algorithm (alg): ${header.alg}`);
      if (!['ES256', 'ES384', 'ES512', 'RS256', 'PS256', 'EdDSA'].includes(header.alg)) {
        this.logWarning(`Unexpected or unsafe signature algorithm detected: ${header.alg}`);
      }
    }

    // typ
    if (!header.typ) {
      this.logWarning("Field 'typ' missing from JWS header (recommended: 'oauth-authz-req+jwt')");
    } else {
      this.logInfo(`Header Type (typ): ${header.typ}`);
      if (header.typ !== 'oauth-authz-req+jwt' && header.typ !== 'JWT') {
        this.logWarning(`Deviating 'typ' header value: '${header.typ}'`);
      }
    }

    // certificate chain (x5c) or JWK
    if (header.x5c) {
      if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
        this.logError("'x5c' header found, but is not a valid array (or empty)");
      } else {
        this.logInfo(`'x5c' certificate chain detected (${header.x5c.length} cert(s))`);
      }
    } else if (header.jwk) {
      this.logInfo("Field 'jwk' found in header");
    } else {
      this.logWarning("Fields 'x5c' & 'jwk' not found in JWS header (trust anchor validation will depend on client_id scheme now)");
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
      this.logError(`Invalid 'response_type' value: '${payload.response_type}'; expected: 'vp_token'.`);
    } else {
      this.logInfo("response_type: 'vp_token' (correct)");
    }

    // response_mode
    if (!payload.response_mode) {
      this.logError("Mandatory field 'response_mode' missing from request object payload");
    } else {
      this.logInfo(`response_mode: ${payload.response_mode}`);
      if (!['direct_post', 'direct_post.jwt'].includes(payload.response_mode)) {
        this.logWarning(`Non-standard response_mode value detected: '${payload.response_mode}'.`);
      }
      if (payload.response_mode === 'direct_post') {
        this.logWarning("response_mode = 'direct_post' (unencrypted); would be invalid for HAIP");
      }
    }

    // response_uri vs redirect_uri
    if (!payload.response_uri) {
      this.logError("Mandatory field 'response_uri' missing for direct_post / direct_post.jwt");
    } else {
      this.logInfo(`response_uri: ${payload.response_uri}`);
      if (!payload.response_uri.startsWith('https://')) {
        this.logError(`'response_uri' MUST be a HTTPS URL: '${payload.response_uri}'`);
      }
    }

    if (payload.redirect_uri) {
      this.logError(`Invalid combination of values: 'redirect_uri' MUST NOT be present for 'response_mode=${payload.response_mode}'`);
    }

    // nonce
    if (!payload.nonce) {
      this.logError("Mandatory field 'nonce' is missing from request object payload");
    } else {
      this.logInfo(`nonce: ${payload.nonce}`);
      if (payload.nonce.length < 16) {
        this.logWarning(`Insufficient entropy of 'nonce': length = ${payload.nonce.length} chars (min 16-32 recommended)`);
      }
    }

    // state
    if (!payload.state) {
      this.logWarning("Field 'state' is missing; recommended for session replay prevention");
    } else {
      this.logInfo(`state: ${payload.state}`);
    }

    // RFC 9101 timestamp: iat & exp
    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload.iat) {
      this.logWarning("Field 'iat' is missing from request object payload (recommended by RFC 9101)");
    } else {
      const iatDate = new Date(payload.iat * 1000).toISOString();
      this.logInfo(`iat: ${payload.iat} (${iatDate})`);
    }

    if (!payload.exp) {
      this.logWarning("Field 'exp' is missing from request object payload (recommended by RFC 9101)");
    } else {
      const expDate = new Date(payload.exp * 1000).toISOString();
      if (payload.exp < nowSec) {
        this.logError(`Request object (JAR) has expired! (exp: ${payload.exp} [${expDate}], current: ${nowSec}).`);
      } else {
        const remainingSec = payload.exp - nowSec;
        this.logInfo(`exp: ${payload.exp} [${expDate}] (still valid for ${remainingSec} seconds from now)`);
      }
    }

    // client_metadata & cncryption keys (for direct_post.jwt)
    this.validateClientMetadata(payload);

    // DCQL query or presentation definition
    this.validateQueries(payload);
  }

  validateClientMetadata(payload) {
    console.log("--- 3. CHECKING CLIENT_METADATA & ENCRYPTION ---");
    const meta = payload.client_metadata;

    if (!meta) {
      if (payload.response_mode === 'direct_post.jwt') {
        this.logError("'client_metadata' is missing, but is required for 'direct_post.jwt' (JWKS)");
      } else {
        this.logWarning("'client_metadata' is missing from request object payload");
      }
      return;
    }

    // JWE encryption key validation (for direct_post.jwt)
    if (payload.response_mode === 'direct_post.jwt') {
      if (!meta.jwks || !Array.isArray(meta.jwks.keys) || meta.jwks.keys.length === 0) {
        this.logError("'client_metadata.jwks.keys' is missing or empty; wallet will be unable to encrypt JWE response");
      } else {
        this.logInfo(`Count of ephemeral encryption keys in JWKS: ${meta.jwks.keys.length}`);
        meta.jwks.keys.forEach((key, index) => {
          this.validateEncryptionJwk(key, index);
        });
      }

      if (!meta.encrypted_response_enc_values_supported) {
        this.logWarning("'client_metadata.encrypted_response_enc_values_supported' is missing (default: A128GCM / A256GCM)");
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
    if (!key.x || !key.y) this.logError(`${prefix}: Public coordinates 'x' or 'y' are missing`);

    if (!key.kid) {
      this.logError(`${prefix}: Mandatory field 'kid' (key ID) is missing`);
    } else {
      this.logInfo(`${prefix}: kid = '${key.kid}'`);
    }

    if (!key.alg) {
      this.logError(`${prefix}: Mandatory field 'alg' is missing (e.g. 'ECDH-ES')`);
    } else {
      this.logInfo(`${prefix}: alg = '${key.alg}'`);
    }

    if (key.use !== 'enc') {
      this.logError(`${prefix}: Fild 'use' must be 'enc' sein, actual: '${key.use}'`);
    } else {
      this.logInfo(`${prefix}: use = 'enc' (correct)`);
    }
  }

  validateQueries(payload) {
    console.log("--- 4. CHECKING DCQL / PRESENTATION DEFINITION ---");

    if (payload.dcql_query) {
      this.logInfo("Request is using DCQL (Digital Credentials Query Language)");
      const dcql = payload.dcql_query;

      if (!dcql.credentials || !Array.isArray(dcql.credentials) || dcql.credentials.length === 0) {
        this.logError("DCQL query 'credentials' array is missing or empty");
      } else {
        this.logInfo(`DCQL query is requesting ${dcql.credentials.length} credential(s)`);
        dcql.credentials.forEach((cred, i) => {
          this.validateDcqlCredential(cred, i);
        });
      }
    } else if (payload.presentation_definition) {
      this.logInfo("Request is using W3C Presentation Definition (DIF)");
    } else {
      this.logError("Neither 'dcql_query' nor 'presentation_definition' found is request object payload");
    }
  }

  validateDcqlCredential(cred, i) {
    const prefix = `DCQL credential[${i}] (id: '${cred.id || 'n/a'}')`;
    if (!cred.id) this.logError(`${prefix}: Mandatory field 'id' is missing`);
    if (!cred.format) this.logError(`${prefix}: Mandatory field 'format' is missing`);

    this.logInfo(`${prefix}: format = '${cred.format}'`);

    if (cred.format === 'mso_mdoc') {
      if (!cred.meta) {
        this.logError(`${prefix}: 'meta' object is missing for mso_mdoc.`);
      } else if (!cred.meta.doctype_value) {
        this.logError(`${prefix}: Mandatory field 'meta.doctype_value' is missing for mso_mdoc!`);
      } else {
        this.logInfo(`${prefix}: meta.doctype_value = '${cred.meta.doctype_value}' (correct)`);
      }
    } else if (cred.format === 'dc+sd-jwt') {
      if (cred.meta && cred.meta.vct_values) {
        this.logInfo(`${prefix}: meta.vct_values = ${JSON.stringify(cred.meta.vct_values)}`);
      }
    }

    if (cred.claims && Array.isArray(cred.claims)) {
      this.logInfo(`${prefix}: ${cred.claims.length} Claim(s) angefordert.`);
      cred.claims.forEach((claim, cIdx) => {
        if (!claim.path || !Array.isArray(claim.path)) {
          this.logError(`${prefix} Claim[${cIdx}]: 'path' muss ein Array von Strings sein.`);
        }
      });
    }
  }

  printReport(header, payload) {
    console.log("=================================================================");
    console.log("                     RESULTS                                     ");
    console.log("=================================================================");

    if (this.report.info.length > 0) {
      console.log("\n[INFO]:");
      this.report.info.forEach(msg => console.log(`  ✓ ${msg}`));
    }

    if (this.report.warnings.length > 0) {
      console.log("\n[WARNINGS]:");
      this.report.warnings.forEach(msg => console.log(`  ⚠️  ${msg}`));
    }

    if (this.report.errors.length > 0) {
      console.log("\n[ERRORS]:");
      this.report.errors.forEach(msg => console.log(`  ❌ ${msg}`));
    }

    console.log("\n-----------------------------------------------------------------");
    if (this.report.valid) {
      console.log("STATUS: ✅ VALID");
    } else {
      console.log("STATUS: ❌ INVALID");
    }
    console.log("-----------------------------------------------------------------\n");

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
