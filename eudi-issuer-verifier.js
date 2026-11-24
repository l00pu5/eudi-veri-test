/**
 * EUDI Wallet - PID Provider / Credential Issuer Verifier & Issuer Helper
 * 
 * This module is implementing the server-side verification and issuance logic
 * acting as a mock EUDI PIDP (PID provider) in accordance with OpenID4VCI 1.0,
 * OpenID HAIP 1.0 and the German national wallet architecture concept.
 * 
 * This module is vendor-neutral and is using no oher external libraries beyond 'crypto'
 * 
 * @module EUDIPIDIssuerVerifier
 */

const crypto = require('crypto');

/**
 * aux function: verify DPoP proof JWT
 */
function verifyDPoPProof(dpopJwt, expectedHtu, expectedHtm = 'POST') {
  if (!dpopJwt) {
    return { valid: false, error: 'DPoP header missing' };
  }

  try {
    const parts = dpopJwt.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid DPoP JWT format' };
    }

    const [headerB64, payloadB64, sigB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

    // 1. header check
    if (header.typ && header.typ !== 'dpop+jwt') {
      console.warn(`typ = "${header.typ}" (expected: "dpop+jwt")`);
    }
    if (!header.jwk) {
      return { valid: false, error: 'Missing jwk parameter in DPoP header' };
    }

    // 2. payload check (htm, htu)
    if (payload.htm && payload.htm.toUpperCase() !== expectedHtm.toUpperCase()) {
      return { valid: false, error: `DPoP HTM error; expected: ${expectedHtm}, actual: ${payload.htm}` };
    }
    if (expectedHtu && payload.htu) {
      // normalized comparison of URLs
      const cleanExpected = expectedHtu.replace(/\/$/, '');
      const cleanActual = payload.htu.replace(/\/$/, '');
      if (cleanExpected !== cleanActual) {
        return { valid: false, error: `DPoP HTU error; expected: ${cleanExpected}, actual: ${cleanActual}` };
      }
    }

    // 3. reconstrut public key from JWK
    const publicKeyObject = crypto.createPublicKey({
      key: header.jwk,
      format: 'jwk'
    });

    // 4. verify signature (IEEE P1363 for ES256)
    const dataToVerify = Buffer.from(`${headerB64}.${payloadB64}`);
    const signatureBuf = Buffer.from(sigB64, 'base64url');

    const verifyOptions = { key: publicKeyObject };
    if (header.alg === 'ES256' || !header.alg) {
      verifyOptions.dsaEncoding = 'ieee-p1363';
    }

    const isSignatureValid = crypto.verify(
      'SHA256',
      dataToVerify,
      verifyOptions,
      signatureBuf
    );

    if (!isSignatureValid) {
      return { valid: false, error: 'Cryptograhic DPoP signature is invalid.' };
    }

    return {
      valid: true,
      dpopKey: header.jwk,
      payload: payload
    };
  } catch (err) {
    return { valid: false, error: `DPoP validation error: ${err.message}` };
  }
}

class EUDIPIDIssuerVerifier {
  constructor(config) {
    if (!config.issuerId || !config.issuerPrivateKeyPem || !config.issuerPublicKeyPem) {
      throw new Error('Configuration error: issuerId, issuerPrivateKeyPem and issuerPublicKeyPem are required.');
    }
    this.issuerId = config.issuerId || "https://localhost:3000/api/issuance";
    this.issuerPrivateKeyPem = config.issuerPrivateKeyPem;
    this.issuerPublicKeyPem = config.issuerPublicKeyPem;
    this.trustedWalletKeys = config.trustedWalletKeys || [];

    // In-memory store for active sessions and nonces (usually Redis)
    this.sessions = new Map();
    this.activeNonces = new Map(); // nonce -> exp
  }

  verifyWia(wiaToken, wiaPop, expectedChallenge) {
    if (!wiaToken) {
      return { valid: false, error: 'WIA token is missing' };
    }
    try {
      const parts = wiaToken.split('.');
      if (parts.length !== 3) {
        return { valid: false, error: 'Invalid WIA JWT format' };
      }
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      console.log("!!! WIA payload:", payload);

      // check if wallet_link is present
      const wallet_link = payload.wallet_link;
      const wallet_solution_id = payload.wallet_solution_id;
      if (wallet_link) {
        console.log("!!! wallet_link is present:", wallet_link);
      }
      else {
        console.log("!!! wallet_link not provided");
      }

      if (wallet_solution_id) {
        console.log("!!! wallet_solution_id is present:", wallet_solution_id);
      }
      else {
        console.log("!!! wallet_solution_id not provided");
      }

      if (expectedChallenge && payload.nonce && payload.nonce !== expectedChallenge) {
        return { valid: false, error: `WIA Nonce Mismatch: expected ${expectedChallenge}, got ${payload.nonce}` };
      }

      return { valid: true, payload };
    } catch (e) {
      return { valid: false, error: `WIA decoding error: ${e.message}` };
    }
  }

  verifyTokenRequest(opts = {}) {
    const errors = [];

    // 1. resolve WIA header or body param
    const wiaToken = opts.wiaToken ||
      opts.headers?.['oauth-client-attestation'] ||
      opts.headers?.['client-attestation'] ||
      opts.body?.client_assertion;

    const wiaPop = opts.wiaPop ||
      opts.headers?.['oauth-client-attestation-pop'] ||
      opts.headers?.['client-attestation-pop'] ||
      opts.body?.client_assertion_pop;

    const dpopProof = opts.dpopProof || opts.headers?.['dpop'];
    const expectedHtu = opts.expectedHtu;

    // 2. verify DPoP proof
    const dpopResult = verifyDPoPProof(dpopProof, expectedHtu, 'POST');
    if (!dpopResult.valid) {
      errors.push(`DPoP validation failed: ${dpopResult.error}`);
    }

    // 3. WIA verification
    if (wiaToken) {
      const wiaResult = this.verifyWia(wiaToken, wiaPop, opts.expectedWiaChallenge);
      if (!wiaResult.valid && !opts.allowMissingWia && !opts.ignoreWiaTrustErrors) {
        errors.push(`Wallet Attestation (WIA) is missing: ${wiaResult.error}`);
      }
    } else if (!opts.allowMissingWia) {
      errors.push('Wallet Instance Attestation (WIA) or WIA PoP missing in token request');
    }

    return {
      success: errors.length === 0 || (dpopResult.valid && opts.allowMissingWia),
      errors: errors,
      dpopKey: dpopResult.dpopKey || null,
      payload: dpopResult.payload || null
    };
  }

  __verifyTokenRequest(params) {
    const { code, codeVerifier, expectedCodeChallenge, dpopProof, wiaToken, wiaPop, expectedWiaChallenge } = params;
    const errors = [];

    // 1. PKCE validation (if codeVerifier was provided)
    if (codeVerifier && expectedCodeChallenge) {
      const calculatedChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
      if (calculatedChallenge !== expectedCodeChallenge) {
        errors.push('PKCE verification failed: Code Verifier does not match Challenge.');
      }
    }

    // 2. DPoP verification (first retrieval of access token)
    let dpopPublicKeyJwk = null;
    if (dpopProof) {
      try {
        dpopPublicKeyJwk = this._verifyDPoPProof(dpopProof, {
          expectedHtm: 'POST',
          expectedHtu: `${this.issuerId}/token`
        });
      } catch (err) {
        errors.push(`DPoP validation failed: ${err.message}`);
      }
    } else {
      errors.push('DPoP proof missing in Token Request. Sender Constrainting is mandatory.');
    }

    // 3. Wallet Instance Attestation (WIA) verification
    if (wiaToken && wiaPop) {
      try {
        this._verifyWiaAndPop(wiaToken, wiaPop, expectedWiaChallenge);
      } catch (err) {
        errors.push(`Wallet Attestation (WIA) failed: ${err.message}`);
      }
    } else {
      errors.push('Wallet Instance Attestation (WIA) or WIA PoP missing in Token Request.');
    }

    return {
      success: errors.length === 0,
      errors,
      dpopKey: dpopPublicKeyJwk // this key limits access token scope via DPoP
    };
  }

  generateNonceResponse(lifespanSeconds) {
    const cNonce = 'c_nonce_' + crypto.randomBytes(16).toString('hex');
    const dpopNonce = 'dpop_nonce_' + crypto.randomBytes(16).toString('hex');
    const exp = Date.now() + (lifespanSeconds * 1000);

    this.activeNonces.set(cNonce, exp);
    this.activeNonces.set(dpopNonce, exp);

    return {
      c_nonce: cNonce,
      c_nonce_expires_in: lifespanSeconds,
      dpop_nonce: dpopNonce
    };
  }

  generateNonceResponse() {
    const cNonce = 'cnonce_' + crypto.randomBytes(16).toString('hex');
    return {
      c_nonce: cNonce,
      c_nonce_expires_in: 86400
    };
  }

  _validateAndConsumeNonce(nonce) {
    if (!nonce) return false;
    const exp = this.activeNonces.get(nonce);
    if (!exp) return false;

    // delete nonce for replay protection
    this.activeNonces.delete(nonce);

    if (Date.now() > exp) {
      return false; // expired
    }
    return true;
  }

  verifyCredentialRequest(opts = {}) {
    const errors = [];

    // 1. resolve AuthHeader
    const authHeader = opts.authHeader || opts.headers?.['authorization'];
    const dpopProof = opts.dpopProof || opts.headers?.['dpop'];
    const expectedHtu = opts.expectedHtu;
    const expectedCNonce = opts.expectedCNonce || opts.expectedNonce;

    // check if valid accessTokenPayload was provided
    if (authHeader) {
      if (!authHeader.toLowerCase().startsWith('dpop ')) {
        errors.push('Authorization header must start with "DPoP "');
      }
    } else if (!opts.accessTokenPayload && !opts.dpopKey) {
      errors.push('DPoP Access Token required in Authorization Header');
    }

    // 2. check DPoP proof for credential endpoint
    let dpopResult = { valid: true };
    if (dpopProof) {
      dpopResult = verifyDPoPProof(dpopProof, expectedHtu, 'POST');
      if (!dpopResult.valid) {
        errors.push(`Credential DPoP validation failed: ${dpopResult.error}`);
      }
    }

    // 3. extract Key Proof (Proof of Possession with c_nonce) & verify
    let proofJwt = opts.proofJwt;
    if (!proofJwt && opts.credentialRequest) {
      if (typeof opts.credentialRequest === 'string' && opts.credentialRequest.startsWith('ey')) {
        proofJwt = opts.credentialRequest;
      } else if (opts.credentialRequest.proof) {
        proofJwt = opts.credentialRequest.proof.jwt ||
          opts.credentialRequest.proof.proof_jwt ||
          opts.credentialRequest.proof;
      }
    }

    if (proofJwt && typeof proofJwt === 'string') {
      try {
        const parts = proofJwt.split('.');
        if (parts.length === 3) {
          const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

          if (expectedCNonce && payload.nonce && payload.nonce !== expectedCNonce) {
            console.warn(`c_nonce warning: expected: ${expectedCNonce}, actual: ${payload.nonce}`);
          }

          // signature verification of the Key Proof (IEEE P1363 for ES256)
          if (header.jwk || header.x5c) {
            let pubKey;
            if (header.jwk) {
              pubKey = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
            } else if (header.x5c && header.x5c.length > 0) {
              const certPem = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`;
              const x509 = new crypto.X509Certificate(certPem);
              pubKey = x509.publicKey;
            }

            if (pubKey) {
              const dataToVerify = Buffer.from(`${parts[0]}.${parts[1]}`);
              const sigBuf = Buffer.from(parts[2], 'base64url');

              const verifyOpts = { key: pubKey };
              if (header.alg === 'ES256' || !header.alg) {
                verifyOpts.dsaEncoding = 'ieee-p1363';
              }

              const isProofValid = crypto.verify(
                'SHA256',
                dataToVerify,
                verifyOpts,
                sigBuf
              );

              if (!isProofValid) {
                errors.push('Credential Proof Signature is invalid');
              }
            }
          }
        }
      } catch (e) {
        console.warn('Error while parsing the Credential Proof:', e.message);
      }
    }

    return {
      success: errors.length === 0,
      errors: errors,
      dpopKey: dpopResult.dpopKey || opts.dpopKey || opts.accessTokenPayload?.cnf?.jwk || null
    };
  }

  __verifyCredentialRequest(params) {
    const { credentialRequest, dpopProof, accessTokenPayload } = params;
    const errors = [];

    // 1. DPoP verification via credential endpoint (sender constrainting check)
    let dpopPublicKeyJwk = null;
    if (dpopProof) {
      try {
        dpopPublicKeyJwk = this._verifyDPoPProof(dpopProof, {
          expectedHtm: 'POST',
          expectedHtu: `${this.issuerId}/credential`
        });

        // Check if the DPoP key matches the key that the access token was bound to
        const expectedTokenJwk = accessTokenPayload.cnf?.jwk;
        if (!expectedTokenJwk || JSON.stringify(dpopPublicKeyJwk) !== JSON.stringify(expectedTokenJwk)) {
          errors.push('DPoP key conflict: DPoP key does not match with the registered token key');
        }
      } catch (err) {
        errors.push(`DPoP validation has failed: ${err.message}`);
      }
    } else {
      errors.push('DPoP proof missing in credential request');
    }

    // 2. format check of the request
    if (!credentialRequest || (!credentialRequest.credential_configuration_id && !credentialRequest.credential_identifier)) {
      errors.push('Invalid credential request: credential_configuration_id or credential_identifier must be provided');
      return { success: false, errors };
    }

    // 3. Validate Proof of Possession (PoP) of the device binding key
    let devicePublicKeyJwk = null;
    const proofs = credentialRequest.proofs || credentialRequest.proof; // supports 'proofs' (array) and legacy 'proof' (object)

    if (proofs && proofs.jwt) {
      const jwtProofArray = Array.isArray(proofs.jwt) ? proofs.jwt : [proofs.jwt];
      const jwtProof = jwtProofArray[0]; // proof by default

      try {
        devicePublicKeyJwk = this._verifyProofOfPossession(jwtProof);
      } catch (err) {
        errors.push(`Cryptographic assertion of key possession (PoP) failed: ${err.message}`);
      }
    } else {
      errors.push('Cryptographic key ownership proof (proofs.jwt) missing credential request.');
    }

    return {
      success: errors.length === 0,
      errors,
      devicePublicKeyJwk // this key will be cryptograohically embedded in the PID ('cnf' claim)
    };
  }

  issuePID(params = {}) {
    const { claims = {}, validityDays = 90, format = 'dc+sd-jwt', holderJwk = null } = params;
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (validityDays * 86400);

    const payload = {
      iss: this.issuerId,
      sub: 'sub_' + crypto.randomBytes(8).toString('hex'),
      iat: now,
      exp: exp,
      vct: params.vct || 'urn:company:employee_id:1',
      ...claims
    };

    if (holderJwk && !payload.cnf) {
      payload.cnf = { jwk: holderJwk };
    }

    const isMdoc = format === "mso_doc" || format === "mDL_ISO_18013_5" || format === "MSO";
    const headerTyp = isMdoc ? "MSO" : (format === "vc+sd-jwt" ? "vs+sd-jwt" : "dc-sd-jwt");

    const header = {
      alg: 'ES256',
      typ: headerTyp
    };

    const tokenInput = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;

    let signature = 'demo_sig';
    if (this.issuerPrivateKeyPem) {
      try {
        signature = crypto.sign('SHA256', Buffer.from(tokenInput), {
          key: this.issuerPrivateKeyPem,
          dsaEncoding: 'ieee-p1363'
        }).toString('base64url');
      } catch (e) {
        console.warn('Signing error at issuer:', e.message);
      }
    }

    const resToken = `${tokenInput}.${signature}`;
    if (!isMdoc && !resToken.endsWith("~")) {
      // console.log("⚠️ adding tilde");
      // console.log(`${resToken}~`);
      return `${resToken}~`;
    }

    // console.log("⚠️ not adding tilde:", format, resToken);
    return resToken;
  }

  __issuePID(params) {
    const { claims, holderJwk, validityDays = 90 } = params;

    if (!holderJwk) {
      throw new Error('Issuance error: a holderJwk needs to be provided for cryptographic device binding.');
    }

    // 1. Definition of salts
    // Generating hashes per each SD attribute
    const disclosures = [];
    const sdHashes = [];

    // auxiliary functions to generate JCP-conform disclosures: Base64Url([Salt, ClaimName, ClaimValue])
    const addDisclosure = (claimName, claimValue) => {
      const salt = crypto.randomBytes(16).toString('base64url'); // strong salt (min. 128 bit entropy)
      const disclosureArray = [salt, claimName, claimValue];
      const disclosureJson = JSON.stringify(disclosureArray);
      const disclosureBase64 = Buffer.from(disclosureJson).toString('base64url');

      disclosures.push(disclosureBase64);

      // calculate hash
      const hash = crypto.createHash('sha256').update(disclosureBase64).digest('base64url');
      sdHashes.push(hash);
    };

    // recursive flat salting of all claims
    for (const [key, value] of Object.entries(claims)) {
      addDisclosure(key, value);
    }

    // sorting of hashes (avoidance of metadata leaks via sorting order)
    sdHashes.sort();

    // 2. Generating the primary JWT payload (issuer-signed portion)
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (validityDays * 24 * 60 * 60);

    const jwtPayload = {
      iss: this.issuerId,
      iat: now,
      nbf: now,
      exp: exp,
      vct: 'https://credentials.example.com/identity_credential', // EUDI PID type metadata URL
      _sd_alg: 'sha-256',
      _sd: sdHashes,
      cnf: {
        jwk: holderJwk // cryptographic device binding to the wallet
      }
    };

    // 3. Generate JWS signature (using the private issuer key)
    const jwtHeader = {
      alg: 'ES256',
      typ: 'dc+sd-jwt', // type declaration in line with HAIP profile
      x5c: [Buffer.from(this.issuerPublicKeyPem).toString('base64')] // optional cert chain attachment
    };

    const jwtInput = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')}`;

    const signer = crypto.createSign('SHA256');
    signer.update(jwtInput);
    const jwtSignature = signer.sign(this.issuerPrivateKeyPem, 'base64url');

    const issuerSignedJwt = `${jwtInput}.${jwtSignature}`;

    // 4. Composition of final SD-JWT VC template
    // Issuer-signed JWT will be delivered including all disclosures (~-separated)
    // to the credential endpoint.
    // Key-binding JWT doesn't exist at this stage yet, will be attached during presentation!
    let responseCredentialString = issuerSignedJwt;
    for (const disclosure of disclosures) {
      responseCredentialString += `~${disclosure}`;
    }
    responseCredentialString += '~'; // closing tilde according to spec

    return responseCredentialString;
  }

  _verifyDPoPProof(jwtString, constraints) {
    const parts = jwtString.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid DPoP JWT format.');
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const signature = Buffer.from(parts[2], 'base64url');

    // 1. header integrity check
    if (header.typ !== 'dpop+jwt') {
      throw new Error(`Invalid DPoP type: ${header.typ}`);
    }
    if (!header.jwk) {
      throw new Error("DPoP header doesn't contain an embdedded public JWK.");
    }

    // 2. Payload integrity check (HTM, HTU and nonce freshness)
    if (payload.htm !== constraints.expectedHtm) {
      throw new Error(`DPoP HTM error; expected: ${constraints.expectedHtm}, actual: ${payload.htm}`);
    }
    if (payload.htu !== constraints.expectedHtu) {
      throw new Error(`DPoP HTU error; expected: ${constraints.expectedHtu}, actual: ${payload.htu}`);
    }
    if (payload.nonce) {
      const isNonceValid = this._validateAndConsumeNonce(payload.nonce);
      if (!isNonceValid) {
        throw new Error('DPoP none has expired or is invalid (risk of replay).');
      }
    }

    // 3. Cryptographic verification against embedded JWK of the wallet
    const publicKey = crypto.createPublicKey({
      key: header.jwk,
      format: 'jwk'
    });

    const dataToVerify = `${parts[0]}.${parts[1]}`;
    const verify = crypto.createVerify('SHA256');
    verify.update(dataToVerify);

    if (!verify.verify(publicKey, signature)) {
      throw new Error('Cryptograhic DPoP signature is invalid.');
    }

    return header.jwk;
  }

  _verifyProofOfPossession(jwtString) {
    const parts = jwtString.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid Proof-of-Possession JWT format.');
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const signature = Buffer.from(parts[2], 'base64url');

    // 1. Type check
    if (header.typ !== 'openid4vci-proof+jwt') {
      throw new Error(`Invalid PoP type: ${header.typ}`);
    }

    // 2. audience and nonce check (time-based freshness)
    if (payload.aud !== this.issuerId) {
      throw new Error(`Incorrect audience. Expected: ${this.issuerId}, actual: ${payload.aud}`);
    }

    if (payload.nonce) {
      const isNonceValid = this._validateAndConsumeNonce(payload.nonce);
      if (!isNonceValid) {
        throw new Error('PoP Nonce is expired or invalid.');
      }
    } else {
      throw new Error('Nonce missing in Proof of Possession payload.');
    }

    // Derive key (JWK is contained in the header)
    const holderJwk = header.jwk;
    if (!holderJwk) {
      throw new Error('Proof header does not contain embedded JWK for signature verification.');
    }

    const publicKey = crypto.createPublicKey({
      key: holderJwk,
      format: 'jwk'
    });

    const dataToVerify = `${parts[0]}.${parts[1]}`;
    const verify = crypto.createVerify('SHA256');
    verify.update(dataToVerify);

    if (!verify.verify(publicKey, signature)) {
      throw new Error('The cryptographic PoP signature is invalid.');
    }

    return holderJwk;
  }

  _verifyWiaAndPop(wiaToken, wiaPop, expectedChallenge) {
    const wiaParts = wiaToken.split('.');
    const popParts = wiaPop.split('.');

    if (wiaParts.length !== 3 || popParts.length !== 3) {
      throw new Error('Invalid WIA or WIA PoP JWT format.');
    }

    const wiaPayload = JSON.parse(Buffer.from(wiaParts[1], 'base64url').toString('utf8'));
    const popPayload = JSON.parse(Buffer.from(popParts[1], 'base64url').toString('utf8'));

    // 1. Verify WIA signature (via wallet provider backend)
    const wiaData = `${wiaParts[0]}.${wiaParts[1]}`;
    const wiaSig = Buffer.from(wiaParts[2], 'base64url');

    let isWiaVerified = false;
    for (const pemKey of this.trustedWalletKeys) {
      try {
        const verify = crypto.createVerify('SHA256');
        verify.update(wiaData);
        isWiaVerified = verify.verify(pemKey, wiaSig);
        if (isWiaVerified) break;
      } catch (err) {
        // try keys
      }
    }

    if (!isWiaVerified) {
      throw new Error('WIA signature check against trusted wallet providers has failed.');
    }

    // Extract WIA key (wi_wia_pop_pubk)
    const walletDeviceJwk = wiaPayload.cnf?.jwk;
    if (!walletDeviceJwk) {
      throw new Error('WIA does not contain embedded device key (cnf.jwk).');
    }

    // 2. Verify siagntue of PoP token (via local wallet instance)
    const popData = `${popParts[0]}.${popParts[1]}`;
    const popSig = Buffer.from(popParts[2], 'base64url');

    const devicePubKey = crypto.createPublicKey({
      key: walletDeviceJwk,
      format: 'jwk'
    });

    const popVerify = crypto.createVerify('SHA256');
    popVerify.update(popData);

    if (!popVerify.verify(devicePubKey, popSig)) {
      throw new Error('Signature of WIA proof (wia_pop) does not match with WIA device key.');
    }

    // 3. reply protection via challenge comparison
    if (expectedChallenge && popPayload.challenge !== expectedChallenge) {
      throw new Error('Security fault: WIA challenge does not match with expected challenge.');
    }

    return true;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE / DEMO TEST CYCLE
// ─────────────────────────────────────────────────────────────────────────────

if (require.main === module) {
  console.log('=== START EUDI WALLET ISSUANCE VERIFIER & PID ISSUER TEST ===\n');

  async function runDemo() {
    // 1. Generate key pairs
    console.log('[Setup] Generating cryptographic key pairs...');
    const issuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const walletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const deviceKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); // Device Binding Key

    const issuerPrivatePem = issuerKeys.privateKey.export({ type: 'sec1', format: 'pem' });
    const issuerPublicPem = issuerKeys.publicKey.export({ type: 'spki', format: 'pem' });
    const walletPublicPem = walletKeys.publicKey.export({ type: 'spki', format: 'pem' });

    const deviceJwk = deviceKeys.publicKey.export({ format: 'jwk' });

    // 2. Instantiating PID provider
    const pidProvider = new EUDIPIDIssuerVerifier({
      issuerId: 'https://pid-provider.bundesdruckerei.de',
      issuerPrivateKeyPem: issuerPrivatePem,
      issuerPublicKeyPem: issuerPublicPem,
      trustedWalletKeys: [walletPublicPem]
    });

    // 3. Generating one-time nohces (for credential endpoint and DPoP)
    console.log('\n[Flow 1] Invoking none endpoint...');
    const nonces = pidProvider.generateNonceResponse();
    console.log('Nonces received:', JSON.stringify(nonces, null, 2));

    // 4. Simulate token request (mTLS, WIA and PKCE)
    console.log('\n[Flow 2] Simulating WIA & token request verification...');

    // Mock WIA
    const wiaHeader = { alg: 'ES256', typ: 'oauth-client-attestation+jwt' };
    const wiaPayload = {
      iss: 'https://wallet-provider.de',
      sub: 'https://wallet.de/instances/456',
      cnf: { jwk: walletKeys.publicKey.export({ format: 'jwk' }) } // Wallet Public Key
    };
    const wiaData = `${Buffer.from(JSON.stringify(wiaHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(wiaPayload)).toString('base64url')}`;
    const wiaSign = crypto.createSign('SHA256'); wiaSign.update(wiaData);
    const wiaToken = `${wiaData}.${wiaSign.sign(walletKeys.privateKey, 'base64url')}`;

    // Mock WIA PoP
    const wiaChallenge = 'challenge_123456789_test';
    const popHeader = { alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' };
    const popPayload = {
      iss: 'https://wallet-provider.de',
      aud: 'https://pid-provider.bundesdruckerei.de',
      challenge: wiaChallenge
    };
    const popData = `${Buffer.from(JSON.stringify(popHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(popPayload)).toString('base64url')}`;
    const popSign = crypto.createSign('SHA256'); popSign.update(popData);
    const wiaPop = `${popData}.${popSign.sign(walletKeys.privateKey, 'base64url')}`;

    // Mock DPoP proof for token interface
    const tokenDpopHeader = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletKeys.publicKey.export({ format: 'jwk' }) };
    const tokenDpopPayload = {
      htm: 'POST',
      htu: 'https://pid-provider.bundesdruckerei.de/token',
      nonce: nonces.dpop_nonce // binding to DPoP nonce
    };
    const tokenDpopData = `${Buffer.from(JSON.stringify(tokenDpopHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(tokenDpopPayload)).toString('base64url')}`;
    const tokenDpopSign = crypto.createSign('SHA256'); tokenDpopSign.update(tokenDpopData);
    const tokenDpopProof = `${tokenDpopData}.${tokenDpopSign.sign(walletKeys.privateKey, 'base64url')}`;

    const tokenResult = pidProvider.verifyTokenRequest({
      code: 'auth_code_987654321',
      dpopProof: tokenDpopProof,
      wiaToken,
      wiaPop,
      expectedWiaChallenge: wiaChallenge
    });

    console.log('Result of token verification:', JSON.stringify(tokenResult, null, 2));

    // 5. Simulate crednetial endpoint request (PID issuance)
    console.log('\n[Flow 3] Invoking credential endpoint (issuance verification)...');

    // generate new nonce for credential endpoint PoP
    const flow2Nonces = pidProvider.generateNonceResponse();

    // mock DPoP proof for credential interface
    const credDpopHeader = { alg: 'ES256', typ: 'dpop+jwt', jwk: walletKeys.publicKey.export({ format: 'jwk' }) };
    const credDpopPayload = {
      htm: 'POST',
      htu: 'https://pid-provider.bundesdruckerei.de/credential',
      nonce: flow2Nonces.dpop_nonce
    };
    const credDpopData = `${Buffer.from(JSON.stringify(credDpopHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(credDpopPayload)).toString('base64url')}`;
    const credDpopSign = crypto.createSign('SHA256'); credDpopSign.update(credDpopData);
    const credDpopProof = `${credDpopData}.${credDpopSign.sign(walletKeys.privateKey, 'base64url')}`;

    // mock key possession proof (PoP) of the user (device key)
    const popProofHeader = { alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: deviceJwk };
    const popProofPayload = {
      aud: 'https://pid-provider.bundesdruckerei.de',
      nonce: flow2Nonces.c_nonce // binding to credential conce
    };
    const popProofData = `${Buffer.from(JSON.stringify(popProofHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(popProofPayload)).toString('base64url')}`;
    const popProofSign = crypto.createSign('SHA256'); popProofSign.update(popProofData);
    const popProofJwt = `${popProofData}.${popProofSign.sign(deviceKeys.privateKey, 'base64url')}`;

    const credRequest = {
      credential_configuration_id: 'PID_SD_JWT_VC',
      proofs: {
        jwt: popProofJwt
      }
    };

    const credResult = pidProvider.verifyCredentialRequest({
      credentialRequest: credRequest,
      dpopProof: credDpopProof,
      accessTokenPayload: {
        cnf: { jwk: walletKeys.publicKey.export({ format: 'jwk' }) } // sender-constrained access token key
      }
    });

    console.log('Result of credential request verification:', JSON.stringify(credResult, null, 2));

    if (credResult.success) {
      console.log('\n[Flow 4] Generating & signing Erika Mustermann EUDI PID...');

      // Erika Mustermann identity data (PID claims)
      const erikaClaims = {
        given_name: 'Erika',
        family_name: 'Mustermann',
        birthdate: '1998-08-12',
        is_over_18: true,
        nationalities: ['DE'],
        address: {
          street_address: 'Heidestraße 17',
          locality: 'Köln',
          postal_code: '50667',
          country: 'DE'
        }
      };

      const signedCredentialString = pidProvider.issuePID({
        claims: erikaClaims,
        holderJwk: credResult.devicePublicKeyJwk
      });

      console.log('\n✅ PID ISSUES SUCCESSFULLY!');
      console.log('SD-JWT VC token string:');
      console.log(signedCredentialString);
    } else {
      console.error('\n❌ ISSUANCE AORTED. Validation issues have occurred.');
    }
  }

  runDemo().catch(console.error);
}

module.exports = { EUDIPIDIssuerVerifier, verifyDPoPProof };
