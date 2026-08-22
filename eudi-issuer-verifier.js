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

class EUDIPIDIssuerVerifier {
  /**
   * Creates a new instance of the Issues/Provider service
   * @param {Object} config - configuration parameters
   * @param {string} config.issuerId - Unique ID of the credential issuer (e.g. https://pid-provider.de)
   * @param {string} config.issuerPrivateKeyPem - private key of the issuer (PEM)
   * @param {string} config.issuerPublicKeyPem - public key of the issuer (PEM)
   * @param {Array<string>} config.trustedWalletKeys - trusted keys of the wallet backend for WIA verification
   */
  constructor(config) {
    if (!config.issuerId || !config.issuerPrivateKeyPem || !config.issuerPublicKeyPem) {
      throw new Error('Configuration error: issuerId, issuerPrivateKeyPem and issuerPublicKeyPem are required.');
    }
    this.issuerId = config.issuerId;
    this.issuerPrivateKeyPem = config.issuerPrivateKeyPem;
    this.issuerPublicKeyPem = config.issuerPublicKeyPem;
    this.trustedWalletKeys = config.trustedWalletKeys || [];

    // In-memory store for active sessions and nonces (usually Redis)
    this.sessions = new Map();
    this.activeNonces = new Map(); // nonce -> exp
  }

  // =============================================================================
  // INTERFACE 1: TOKEN ENDPOINT (DPoP & WIA VALIDATION)
  // =============================================================================

  /**
   * Validates an incoming token request (pillar 4: wallet authenticity & DPoP key binding)
   * 
   * @param {Object} params - request parameters
   * @param {string} params.code - authorization code or refresh token
   * @param {string} params.codeVerifier - PKCE Code Verifier (in case of Auth Code Flow)
   * @param {string} params.expectedCodeChallenge - previously saved PKCE Code Challenge
   * @param {string} params.dpopProof - DPoP Proof Token (JWT) of the client
   * @param {string} params.wiaToken - WIA JWT from the wallet backend
   * @param {string} params.wiaPop - WIA Proof of Possession (PoP) JWT
   * @param {string} params.expectedWiaChallenge - previously generated challenge
   * @returns {Object} validation result with DPoP key binding (public key)
   */
  verifyTokenRequest(params) {
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

  // =============================================================================
  // INTERFACE 2: NONCE GENERATION (c_nonce & dpop_nonce)
  // =============================================================================

  /**
   * Generates a fresh nonce pair for securing attestations
   * 
   * @param {number} [lifespanSeconds=300] - Validity period of nonce (default: 5min)
   * @returns {Object} Nonce Response Objejt (c_nonce & dpop_nonce)
   */
  generateNonceResponse(lifespanSeconds = 300) {
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

  /**
   * Checks if none if valid and still active
   * Consumes nonce directly (Single Use for High Assurance)
   */

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

  // =============================================================================
  // INTERFACE 3: CREDENTIAL ENDPOINT
  // =============================================================================

  /**
   * Verifies an incoming credential request
   * Checks DPoP (Access Token Binding) + cryptographic key PoP (Proof of Possession).
   * 
   * @param {Object} params - validation context
   * @param {Object} params.credentialRequest - JSON body of the credential request
   * @param {string} params.dpopProof - DPoP Proof Token from the HTTP header
   * @param {Object} params.accessTokenPayload - decoded Access Token (with cnf.jwk coupling)
   * @returns {Object} validation result with the verified device binding key of the user
   */
  verifyCredentialRequest(params) {
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
          errors.push('DPoP-Schlüsselkonflikt: Der DPoP-Schlüssel entspricht nicht dem registrierten Token-Schlüssel (Sender-Constraint verletzt).');
        }
      } catch (err) {
        errors.push(`DPoP-Validierung fehlgeschlagen: ${err.message}`);
      }
    } else {
      errors.push('DPoP-Proof fehlt im Credential-Request.');
    }

    // 2. format check of the request
    if (!credentialRequest || (!credentialRequest.credential_configuration_id && !credentialRequest.credential_identifier)) {
      errors.push('Ungültiger Credential-Request: Es muss eine credential_configuration_id oder ein credential_identifier übergeben werden.');
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

  // =============================================================================
  // INTERFACE 4: PID SIGNATURE & ISSUANCE (SD-JWT VC)
  // =============================================================================

  /**
   * Generates a signed SD-JWT VC for the provided claims and binds it to the user's device key
   * 
   * @param {Object} params - Ausstellungsparameter
   * @param {Object} params.claims - Klartext-Claims (z. B. Erika Mustermanns Daten)
   * @param {Object} params.holderJwk - Der verifizierte öffentliche Device-Binding-Schlüssel der Wallet (cnf.jwk)
   * @param {number} [validityDays=90] - Gültigkeitsdauer des Credentials in Tagen
   * @returns {string} Kompakt-serialisiertes SD-JWT VC (Aussteller-signiertes JWT)
   */
  issuePID(params) {
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

  // =============================================================================
  // AUX METHODS (cryptography & verification)
  // =============================================================================

  /**
   * validation helper for DPoP proof JWTs.
   */
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
      throw new Error(`DPoP HTM error. Expected: ${constraints.expectedHtm}, actual: ${payload.htm}`);
    }
    if (payload.htu !== constraints.expectedHtu) {
      throw new Error(`DPoP HTU fehler. Expected: ${constraints.expectedHtu}, actual: ${payload.htu}`);
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

  /**
   * Validation helper for Key Proof of Possession JWTs (from the credential endpoint).
   */
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

  /**
   * Validation helper for WIA & PoP
   */
  _verifyWiaAndPop(wiaToken, wiaPop, expectedChallenge) {
    const wiaParts = wiaToken.split('.');
    const popParts = wiaPop.split('.');

    if (wiaParts.length !== 3 || popParts.length !== 3) {
      throw new Error('nvalid WIA or WIA PoP JWT format.');
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

module.exports = { EUDIPIDIssuerVerifier };
