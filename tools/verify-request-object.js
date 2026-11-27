const crypto = require('crypto');

function extractAllowedClaimsFromWrprc(wrprcPayload) {
  // console.log("!", wrprcPayload);
  if (wrprcPayload.credentials && wrprcPayload.credentials.length > 0) {
    if (wrprcPayload.credentials.length === 1) {
      // console.log("!!", wrprcPayload.credentials[0].claim);
      return wrprcPayload.credentials[0].claim;
    }
  }
  if (!wrprcPayload || typeof wrprcPayload !== 'object') return [];
  const claims = new Set();
  function collect(item) {
    if (!item) return;
    if (typeof item === 'string') {
      claims.add(item);
    } else if (typeof item === 'object') {
      if (Array.isArray(item.path)) {
        claims.add(item.path.join('.'));
      } else if (typeof item.path === 'string') {
        claims.add(item.path);
      } else if (typeof item.name === 'string') {
        claims.add(item.name);
      } else if (typeof item.claim === 'string') {
        claims.add(item.claim);
      }
    }
  }
  function scanClaimsList(list) {
    if (Array.isArray(list)) list.forEach(collect);
  }
  function scanCredArray(arr) {
    if (Array.isArray(arr)) {
      arr.forEach(cred => {
        if (cred && typeof cred === 'object') {
          scanClaimsList(cred.allowed_claims);
          scanClaimsList(cred.claims);
          scanClaimsList(cred.requested_claims);
        }
      });
    }
  }
  scanClaimsList(wrprcPayload.claims);
  scanClaimsList(wrprcPayload.allowed_claims);
  scanClaimsList(wrprcPayload.requested_claims);
  scanClaimsList(wrprcPayload.authorized_claims);
  scanCredArray(wrprcPayload.allowed_credentials);
  scanCredArray(wrprcPayload.credentials);

  const vinfo = wrprcPayload.verifier_info || wrprcPayload.registration_metadata || {};
  if (vinfo && typeof vinfo === 'object') {
    scanClaimsList(vinfo.claims);
    scanClaimsList(vinfo.allowed_claims);
    scanClaimsList(vinfo.requested_claims);
    scanClaimsList(vinfo.authorized_claims);
    scanCredArray(vinfo.allowed_credentials);
    scanCredArray(vinfo.credentials);
  }
  return Array.from(claims);
}

function parseBase64UrlJson(str) {
  try {
    const jsonStr = Buffer.from(str, 'base64url').toString('utf8');
    return JSON.parse(jsonStr);
  } catch (e) {
    throw new Error(`Base64URL JSON decoding has failed: ${e.message}`);
  }
}

function verifyRequestObject(jwtString, options = {}) {
  const report = {
    valid: false,
    errors: [],
    warnings: [],
    checks: [],
    header: null,
    payload: null,
    wrpacInfo: null,
    wrprcInfo: null,
    overaskingCheck: null
  };

  function addCheck(name, success, detail) {
    report.checks.push({ name, success, detail });
    if (!success) {
      report.errors.push(`[${name}] ${detail}`);
    }
  }

  function addWarning(name, detail) {
    report.warnings.push(`[${name}] ${detail}`);
  }

  try {
    // -------------------------------------------------------------------------
    // 1. JWS formsat check
    // -------------------------------------------------------------------------
    if (!jwtString || typeof jwtString !== 'string') {
      throw new Error('No valid JWT string provided');
    }

    const parts = jwtString.trim().split('.');
    if (parts.length !== 3) {
      throw new Error(`Invalid JWS Compact Serialization: 3 segments expected (Header.Payload.Signature), ${parts.length} received instead`);
    }

    const headerB64 = parts[0];
    const payloadB64 = parts[1];
    const signatureB64 = parts[2];

    const header = parseBase64UrlJson(headerB64);
    const payload = parseBase64UrlJson(payloadB64);

    report.header = header;
    report.payload = payload;

    // 1.1 Header Typ check
    const isTypValid = header.typ === 'oauth-authz-req+jwt';
    addCheck(
      'Header Typ',
      isTypValid,
      isTypValid ? `Correkt (typ = "${header.typ}")` : `Invalid typ header: expected "oauth-authz-req+jwt", actual "${header.typ || 'none'}".`
    );

    // 1.2 Signature algo
    const supportedAlgs = ['ES256', 'ES384', 'ES512', 'RS256', 'PS256', 'Ed25519'];
    const isAlgValid = supportedAlgs.includes(header.alg);
    addCheck(
      'Signature Algorithm',
      isAlgValid,
      isAlgValid ? `Supported (alg = "${header.alg}")` : `Unsupported algorithm: "${header.alg}"; expected one of [${supportedAlgs.join(', ')}].`
    );

    // -------------------------------------------------------------------------
    // 2. WRPAC verification
    // -------------------------------------------------------------------------
    if (!header.x5c || !Array.isArray(header.x5c) || header.x5c.length === 0) {
      addCheck('WRPAC (x5c Header)', false, 'Missing or empty "x5c" header; WRPAC is mandatory');
    } else {
      const leafCertB64 = header.x5c[0];
      const certDerBuffer = Buffer.from(leafCertB64, 'base64');

      let x509Cert = null;
      try {
        x509Cert = new crypto.X509Certificate(certDerBuffer);
      } catch (certErr) {
        addCheck('WRPAC parsing', false, `First cert from x5c could not be prased as X.509: ${certErr.message}`);
      }

      if (x509Cert) {
        // SHA-256 hash of WRPAC DER buffer for x509_hash client ID
        const calculatedHash = crypto.createHash('sha256').update(certDerBuffer).digest('base64url');
        const expectedHashClientId = `x509_hash:${calculatedHash}`;

        report.wrpacInfo = {
          subject: x509Cert.subject,
          issuer: x509Cert.issuer,
          validFrom: x509Cert.validFrom,
          validTo: x509Cert.validTo,
          fingerprint256: x509Cert.fingerprint256,
          calculatedHashClientId: expectedHashClientId
        };

        addCheck('WRPAC Validity', new Date() >= new Date(x509Cert.validFrom) && new Date() <= new Date(x509Cert.validTo), `Valid from ${x509Cert.validFrom} until ${x509Cert.validTo}`);

        // Client ID hash matching
        const isClientIdMatching = payload.client_id === expectedHashClientId;
        addCheck(
          'Client ID binding (x509_hash)',
          isClientIdMatching,
          isClientIdMatching
            ? `Correctly bound to WRPAC DER hash (${expectedHashClientId})`
            : `Client ID mismatch; request client_id: "${payload.client_id}", calculated from WRPAC: "${expectedHashClientId}".`
        );

        // signature validation of request object against WRPAC public key
        try {
          const dataToVerify = Buffer.from(`${headerB64}.${payloadB64}`);
          const sigBuffer = Buffer.from(signatureB64, 'base64url');

          let isSigValid = false;
          if (header.alg.startsWith('ES')) {
            isSigValid = crypto.verify('SHA256', dataToVerify, { key: x509Cert.publicKey, dsaEncoding: 'ieee-p1363' }, sigBuffer);
          } else {
            isSigValid = crypto.verify('SHA256', dataToVerify, x509Cert.publicKey, sigBuffer);
          }

          addCheck(
            'Request Object Signature (WRPAC)',
            isSigValid,
            isSigValid ? 'Signature of Request Object successfully verified against WRPAC public key' : 'Signature check of Request Object has failed'
          );
        } catch (sigErr) {
          addCheck('Request Object Signature (WRPAC)', false, `Error during signature check: ${sigErr.message}`);
        }
      }
    }

    // -------------------------------------------------------------------------
    // 3. Payload & claims validation
    // -------------------------------------------------------------------------
    addCheck('ResponseType Claim', payload.response_type === 'vp_token', `response_type = "${payload.response_type}" (expectd: "vp_token")`);
    addCheck('ResponseMode Claim', payload.response_mode === 'direct_post.jwt' || payload.response_mode === 'direct_post', `response_mode = "${payload.response_mode}"`);
    addCheck('Nonce Claim', typeof payload.nonce === 'string' && payload.nonce.length >= 8, `nonce present (lenth: ${payload.nonce ? payload.nonce.length : 0})`);
    addCheck('State Claim', typeof payload.state === 'string' && payload.state.length > 0, `state present ("${payload.state}")`);

    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp) {
      const isNotExpired = payload.exp > nowSec;
      addCheck('Expiration date (exp)', isNotExpired, isNotExpired ? `Valid from ${new Date(payload.exp * 1000).toISOString()}` : `Request Object expired at ${new Date(payload.exp * 1000).toISOString()}`);
    } else {
      addWarning('Expiration date (exp)', 'No "exp" claim present in Request Object');
    }

    // -------------------------------------------------------------------------
    // 4. WRPRC validity check
    // -------------------------------------------------------------------------
    let wrprcToken = null;
    let wrprcPayload = null;
    let wrprcHeader = null;

    if (payload.verifier_info && Array.isArray(payload.verifier_info)) {
      const regCertObj = payload.verifier_info.find(item =>
        item.format === 'registration_cert' || item.format === 'rc-wrp+jwt' || (typeof item.data === 'string' && item.data.startsWith('ey'))
      );
      if (regCertObj) {
        wrprcToken = regCertObj.data || regCertObj.jwt || (typeof regCertObj === 'string' ? regCertObj : null);
      }
    }

    if (!wrprcToken) {
      addCheck('WRPRC (verifier_info)', false, 'No WRPRC found in "verifier_info"');
    } else {
      try {
        const wrprcParts = wrprcToken.trim().split('.');
        wrprcHeader = parseBase64UrlJson(wrprcParts[0]);
        wrprcPayload = parseBase64UrlJson(wrprcParts[1]);

        const isWrprcTypValid = wrprcHeader.typ === 'rc-wrp+jwt' || wrprcHeader.typ === 'registration_cert';
        addCheck('WRPRC Header Typ', isWrprcTypValid, `typ = "${wrprcHeader.typ}"`);

        report.wrprcInfo = {
          header: wrprcHeader,
          payload: wrprcPayload,
          subject: wrprcPayload.sub || wrprcPayload.sub_ln || wrprcPayload.name || 'N/A',
          legalName: wrprcPayload.sub_ln || wrprcPayload.name || 'N/A',
          allowedClaims: extractAllowedClaimsFromWrprc(wrprcPayload)
        };

        addCheck('WRPRC Identity', true, `Legal Name: "${report.wrprcInfo.legalName}", Sub: "${report.wrprcInfo.subject}"`);

      } catch (wrprcErr) {
        addCheck('WRPRC Decoding', false, `WRPRC JWT could not be decoded: ${wrprcErr.message}`);
      }
    }

    // -------------------------------------------------------------------------
    // 5. Cross calidation: WRPAC <-> WRPRC identity
    // -------------------------------------------------------------------------
    if (report.wrpacInfo && report.wrprcInfo) {
      const acSub = report.wrpacInfo.subject;
      const rcSub = report.wrprcInfo.subject;
      const rcLegalName = report.wrprcInfo.legalName;

      // check org names
      const isIdentityMatching = (acSub && rcSub && (acSub.includes(rcSub) || rcSub.includes(acSub) || acSub.includes(rcLegalName)));

      addCheck(
        'WRPAC <-> WRPRC Identity comparison',
        isIdentityMatching,
        isIdentityMatching
          ? `Identity matching; WRPAC subject: "${acSub}", WRPRC name: "${rcLegalName}"`
          : `Potential mismatch between WRPAC and WRPRC; AC subject: "${acSub}", RC subject: "${rcSub}"`
      );
    }

    // -------------------------------------------------------------------------
    // 6. Overasking check
    // -------------------------------------------------------------------------
    if (payload.dcql_query && payload.dcql_query.credentials) {
      const requestedClaims = [];
      payload.dcql_query.credentials.forEach(cred => {
        const credId = cred.id;
        const format = cred.format;
        if (cred.claims && Array.isArray(cred.claims)) {
          cred.claims.forEach(c => {
            requestedClaims.push({
              credId,
              format,
              path: c.path,
              pathStr: Array.isArray(c.path) ? c.path.join('.') : String(c.path)
            });
          });
        }
      });

      const allowedClaims = report.wrprcInfo?.allowedClaims || [];

      const unauthorizedClaims = [];
      requestedClaims.forEach(reqClaim => {
        // check if claims in allowed claims list
        let isAllowed = false;
        if (allowedClaims.length === 0) {
          isAllowed = true;
        } else {
          isAllowed = allowedClaims.some(allowed => {
            if (typeof allowed === 'string') {
              return allowed === reqClaim.pathStr || allowed.endsWith(reqClaim.pathStr) || reqClaim.pathStr.endsWith(allowed);
            } else if (allowed && allowed.path) {
              const aPath = Array.isArray(allowed.path) ? allowed.path.join('.') : String(allowed.path);
              return aPath === reqClaim.pathStr;
            }
            return false;
          });
        }

        if (!isAllowed) {
          unauthorizedClaims.push(reqClaim.pathStr);
        }
      });

      const isOverasking = unauthorizedClaims.length > 0;
      report.overaskingCheck = {
        requestedCount: requestedClaims.length,
        unauthorizedClaims: unauthorizedClaims
      };

      addCheck(
        'Overasking Check (DCQL vs WRPRC)',
        !isOverasking,
        !isOverasking
          ? `All ${requestedClaims.length} requested attributes are allowed per WRPRC`
          : `OVERASKING; following ${unauthorizedClaims.length} attributes are not allowed per WRPRC: [${unauthorizedClaims.join(', ')}]`
      );
    }

    report.valid = report.errors.length === 0;

  } catch (globalErr) {
    report.errors.push(`Generic verification error: ${globalErr.message}`);
    report.valid = false;
  }

  return report;
}

// -------------------------------------------------------------------------
// Output
// -------------------------------------------------------------------------
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('Usage:\n  node verify-request-object.js "<Request-Object-JWT-String>"');
    process.exit(1);
  }

  const jwtInput = args[0];
  const report = verifyRequestObject(jwtInput);

  console.log('================================================================================');
  console.log('         EUDI WALLET REQUEST OBJECT (JAR) VALIDATOR');
  console.log('================================================================================');

  console.log('🔍 CHECK LIST:');
  report.checks.forEach(check => {
    const symbol = check.success ? '✅ PASS' : '❌ FAIL';
    console.log(`  [${symbol}] ${check.name.padEnd(38)} : ${check.detail}`);
  });

  if (report.warnings.length > 0) {
    console.log('⚠️ WARNINGS:');
    report.warnings.forEach(w => console.log(`  ${w}`));
  }

  if (report.wrpacInfo) {
    console.log('WRP-AC (Access Certificate):');
    console.log(`  Subject            : ${report.wrpacInfo.subject}`);
    console.log(`  Issuer             : ${report.wrpacInfo.issuer}`);
    console.log(`  Validity           : ${report.wrpacInfo.validFrom} bis ${report.wrpacInfo.validTo}`);
    console.log(`  Calculated ClientID: ${report.wrpacInfo.calculatedHashClientId}`);
  }

  if (report.wrprcInfo) {
    console.log('WRP-RC (Registration Certificate):');
    console.log(`  Legal Name / Org   : ${report.wrprcInfo.legalName}`);
    console.log(`  Subject Identifier : ${report.wrprcInfo.subject}`);
    console.log(`  Allowed Claims     : ${JSON.stringify(report.wrprcInfo.allowedClaims)}`);
  }

  console.log('--------------------------------------------------------------------------------');
  console.log(`VERIFICATION RESULT: ${report.valid ? '✅ VALID' : '❌ INVALID'}`);
  console.log('--------------------------------------------------------------------------------');
}

module.exports = { verifyRequestObject, parseBase64UrlJson };
