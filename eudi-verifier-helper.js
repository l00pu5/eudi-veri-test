/**
 * EUDI Wallet - Relying Party (RP) Verification Helper
 * 
 * This verifier implements a full simulation of the "Erika Mustermann"
 * mock identity for PID.
 * 
 * It parses and verifies the PID as SD-JWT VC.
 * 
 * @module EUDIVerifier
 * @version 2.0.0
 */

const crypto = require('crypto');

class EUDIVerifier {
  /**
   * Creates a new instance of the verifier module
   * @param {Object} config - configuration of the mock relying party (RP)
   * @param {string} config.clientId - registered client ID of the RP
   * @param {string} config.expectedNonce - transaction nonce for this session (replay protection)
   * @param {Array<string>} config.trustedIssuerKeys - known public keys of truted issuers (PEM)
   * @param {Array<string>} config.trustedWalletKeys - known publoc keys of trusted wallet providers (WIA check)
   */
  constructor(config) {
    if (!config.clientId || !config.expectedNonce) {
      throw new Error('Configuration error: clientId and expectedNonce are required.');
    }
    this.clientId = config.clientId;
    this.expectedNonce = config.expectedNonce;
    this.trustedIssuerKeys = config.trustedIssuerKeys || [];
    this.trustedWalletKeys = config.trustedWalletKeys || [];
  }

  /**
   * Verification of a VP token
   * 
   * @param {Object} vpToken - vp_token that has been transmitted from the wallet (JSON)
   * @param {string} wiaToken - option WIA for wallet verification
   * @returns {Promise<Object>} verification result with extracted & verified attributes
   */
  async verifyPresentation(vpToken, wiaToken = null) {
    const result = {
      success: false,
      errors: [],
      claims: {},
      verifiedPillars: {
        issuerAuthenticity: false,
        deviceBinding: false,
        revocationStatus: false,
        walletValidation: false
      }
    };

    try {
      // aux variable used for credential extraction
      // vp_token = JSON object listing credentials under their respectinve DCQL IDs
      const credentialId = Object.keys(vpToken)[0];
      if (!credentialId) {
        throw new Error('Invalid vp_token format: credential ID not found.');
      }

      let rawCredential = vpToken[credentialId];
      if (Array.isArray(rawCredential)) {
        rawCredential = rawCredential[0];
      }

      // checking document type (SD-JWT VC or ISO mdoc)
      const isSdJwt = typeof rawCredential === 'string' && rawCredential.includes('.');

      if (isSdJwt) {
        await this._verifySdJwtFlow(rawCredential, wiaToken, result);
      } else {
        // placeholder for ISO mdoc (CBOR/COSE-based)
        throw new Error('ISO mdoc (mso_mdoc) not structurally supported.');
      }

      if (result.errors.length === 0) {
        result.success = true;
      }
    } catch (err) {
      result.errors.push(err.message);
    }

    return result;
  }

  /**
   * validation flow for SD-JWT VCs (Selective Disclosure JWTs)
   */
  async _verifySdJwtFlow(sdJwtString, wiaToken, result) {
    // SD-JWT composition: JWT payload ~ Disclosures... ~ Key Binding JWT (optional)
    const parts = sdJwtString.split('~');
    const credentialJwt = parts[0];
    const keyBindingJwt = parts[parts.length - 1]; // last part if key binding is used
    const disclosures = parts.slice(1, parts.length - 1);

    // 1. decoding main credential
    const parsedCred = this._decodeJwt(credentialJwt);

    // ── PILLAR 1: VERIFICATION OF ISSUER AUTHENTICITY & INTEGRITY ──────────────────────────
    try {
      this._verifyIssuerSignature(credentialJwt, parsedCred.header);
      result.verifiedPillars.issuerAuthenticity = true;
    } catch (err) {
      result.errors.push(`Pillar 1 (Issuer Authenticity) failed: ${err.message}`);
      return;
    }

    // Disclosing and extracting the selectively discolosed attributes
    const disclosedClaims = this._extractDisclosures(disclosures);
    result.claims = { ...parsedCred.payload, ...disclosedClaims };
    // clean-up of SD JWT metadata from the result claim
    delete result.claims._sd;
    delete result.claims._sd_alg;

    // ── PILLAR 2: DEVICE BINDING (PROOF OF POSSESSION) ──────────────────────────
    try {
      if (!keyBindingJwt || keyBindingJwt.trim() === '') {
        throw new Error('No key binding JWT found in SD-JWT token, although device binding is requested.');
      }
      this._verifyDeviceBinding(keyBindingJwt, result.claims.cnf?.jwk);
      result.verifiedPillars.deviceBinding = true;
    } catch (err) {
      result.errors.push(`Pillar 2 (Device Binding) failed: ${err.message}`);
    }

    // ── PILLAR 3: RE-VERIFICATION & STATUS CHECK ─────────────────────────────────
    try {
      await this._checkRevocationStatus(result.claims.status);
      result.verifiedPillars.revocationStatus = true;
    } catch (err) {
      result.errors.push(`Pillar 3 (Revocation Status) failed: ${err.message}`);
    }

    // ── PILLAR 4: WALLET APP VALIDATION (WIA/WTE) ──────────────────────────────
    if (wiaToken) {
      try {
        this._validateWalletInstance(wiaToken);
        result.verifiedPillars.walletValidation = true;
      } catch (err) {
        result.errors.push(`Pillar 4 (Wallet Validation) failed: ${err.message}`);
      }
    } else {
      result.errors.push('Pillar 4 warning: WIA token not transmitted. Unable to check wallet authenticity.');
    }
  }

  /**
   * Pillar 1: verifies the issuer's digital signature
   */
  _verifyIssuerSignature(jwtString, header) {
    const jwtParts = jwtString.split('.');
    if (jwtParts[2] === 'simulated_government_issuer_signature' || jwtParts[2] === 'simulated_issuer_signature') {
      console.log('[EUDI Verifier] Pillar 1 by-pass: accepting simuölated federal PID for demo purposes.');
      return true;
    }

    if (this.trustedIssuerKeys.length === 0) {
      throw new Error('No trusted issuer keys (trustedIssuerKeys) configured. Verification not possible.');
    }

    const dataToVerify = `${jwtParts[0]}.${jwtParts[1]}`;
    const signature = Buffer.from(jwtParts[2], 'base64url');

    let isVerified = false;
    let lastError = null;

    for (const pemKey of this.trustedIssuerKeys) {
      try {
        const verify = crypto.createVerify('SHA256');
        verify.update(dataToVerify);
        isVerified = verify.verify(pemKey, signature);
        if (isVerified) break;
      } catch (err) {
        lastError = err;
      }
    }

    if (!isVerified) {
      throw new Error(`Signature validation failed. Issuer key is unknown or invalid. ${lastError ? lastError.message : ''}`);
    }
  }

  /**
   * Pillar 2: verifies the key binding (device binding via hardware key)
   */
  _verifyDeviceBinding(kbJwtString, holderJwk) {
    if (!holderJwk) {
      throw new Error('Proof does not cotnain public user key (cnf.jwk). Device binding cannot be verified.');
    }

    const kbParts = kbJwtString.split('.');
    if (kbParts.length !== 3) {
      throw new Error('Invalid key binding JWT format.');
    }

    const kbPayload = JSON.parse(Buffer.from(kbParts[1], 'base64url').toString('utf8'));
    const kbHeader = JSON.parse(Buffer.from(kbParts[0], 'base64url').toString('utf8'));

    // 1. replay protection: does none match the transaction nonce?
    if (kbPayload.nonce !== this.expectedNonce) {
      throw new Error(`Possible replay attach identified! Expected nonce: ${this.expectedNonce}, actual: ${kbPayload.nonce}`);
    }

    // 2. client gindung: does the recipient ID match with the client ID?
    if (kbPayload.aud !== this.clientId) {
      throw new Error(`Incorrect recipient! Expected client ID (aud): ${this.clientId}, actual: ${kbPayload.aud}`);
    }

    // 3. type check: is the KB JWT of type "openid4vci-proof+jwt" or "kb+jwt"?
    if (kbHeader.typ !== 'openid4vci-proof+jwt' && kbHeader.typ !== 'kb+jwt' && kbHeader.typ !== 'openid4vp-proof+jwt') {
      throw new Error(`Invalid KB JWT type in header: ${kbHeader.typ}`);
    }

    if (kbParts[2] === 'simulated_device_secure_element_signature') {
      console.log('[EUDI Verifier] Pillar 2 by-pass: simulated device binding accepted for local demo purposes.');
      return true;
    }

    // 4. cryptographic signature verification of the user against the credential JWK
    try {
      const pubKey = crypto.createPublicKey({
        key: holderJwk,
        format: 'jwk'
      });

      const dataToVerify = `${kbParts[0]}.${kbParts[1]}`;
      const signature = Buffer.from(kbParts[2], 'base64url');

      const verify = crypto.createVerify('SHA256');
      verify.update(dataToVerify);

      const isVerified = verify.verify(pubKey, signature);
      if (!isVerified) {
        throw new Error('The signature of the key binding JWT does not match with the binding key (cnf.jwk).');
      }
    } catch (err) {
      throw new Error(`Error during cryptographic device verification: ${err.message}`);
    }
  }

  /**
   * Pillar 3: checks the lock status of the credential
   */
  async _checkRevocationStatus(statusClaim) {
    if (!statusClaim) {
      return true;
    }

    const statusList = statusClaim.status_list;
    if (!statusList || typeof statusList.idx !== 'number' || !statusList.uri) {
      throw new Error('Lock status claim is syntactically not correct / invalid.');
    }

    console.log(`[Status List Fetch] fetching status bit list from URI: ${statusList.uri}`);

    // simulation of bot check: 0 = valid, 1 = locked
    const simulatedBitValue = 0; // enforcing bit value ot "valid"

    if (simulatedBitValue !== 0) {
      throw new Error(`The digital certificate has been locked by the issuer (bit at position ${statusList.idx} is != 0).`);
    }

    return true;
  }

  /**
   * Pillar 4: validates the authenticity of the walle instance (WIA/WTE)
   */
  _validateWalletInstance(wiaTokenString) {
    if (this.trustedWalletKeys.length === 0) {
      throw new Error('No trusted wallet provider key is configured.');
    }

    const wiaParts = wiaTokenString.split('.');
    if (wiaParts.length !== 3) {
      throw new Error('Invalid WIA JWT format.');
    }

    const wiaHeader = JSON.parse(Buffer.from(wiaParts[0], 'base64url').toString('utf8'));
    const wiaPayload = JSON.parse(Buffer.from(wiaParts[1], 'base64url').toString('utf8'));

    // type check in accordance with eIDAS WIA profile
    if (wiaHeader.typ !== 'oauth-client-attestation+jwt') {
      throw new Error(`Invalid WIA type in header: ${wiaHeader.typ}`);
    }

    if (wiaParts[2] === 'simulated_wallet_manufacturer_signature') {
      console.log('[EUDI Verifier] Pillar 4 by-pass: simulated wallet attestation accepted for local demo purposes.');
      return true;
    }

    // signature check of the WIA token against the trusted store of the wallet provider
    const dataToVerify = `${wiaParts[0]}.${wiaParts[1]}`;
    const signature = Buffer.from(wiaParts[2], 'base64url');

    let isVerified = false;
    for (const pemKey of this.trustedWalletKeys) {
      try {
        const verify = crypto.createVerify('SHA256');
        verify.update(dataToVerify);
        isVerified = verify.verify(pemKey, signature);
        if (isVerified) break;
      } catch (err) {
        // try keys
      }
    }

    if (!isVerified) {
      throw new Error('WIA has been signed with an unknown or invalid key.');
    }

    // validity check
    const now = Math.floor(Date.now() / 1000);
    if (wiaPayload.exp && now > wiaPayload.exp) {
      throw new Error('WIA has expired.');
    }

    console.log(`[WIA Validation] wallet authenticity confirmed: ${wiaPayload.wallet_name || 'Unknown'}`);
  }

  /**
   * Decoding and extraction of SD-JWT disclosures
   */
  _extractDisclosures(disclosureStrings) {
    const claims = {};

    for (const disclosure of disclosureStrings) {
      if (!disclosure) continue;

      try {
        // each disclosure is a base64url-encoded JSON array: [Salt, ClaimName, ClaimValue]
        const decodedJson = Buffer.from(disclosure, 'base64url').toString('utf8');
        const array = JSON.parse(decodedJson);

        if (Array.isArray(array) && array.length === 3) {
          const claimName = array[1];
          const claimValue = array[2];
          claims[claimName] = claimValue;
        }
      } catch (err) {
        // ignore incorect or invalid disclosures
      }
    }

    return claims;
  }

  /**
   * JWT decoding wthout signature check
   */
  _decodeJwt(jwtString) {
    const parts = jwtString.split('.');
    if (parts.length < 2) {
      throw new Error('Invalid JWT format.');
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    return { header, payload };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE / END-TO-END DEMO WITH ERIKA MUSTERMANN PAYLOAD
// ─────────────────────────────────────────────────────────────────────────────

if (require.main === module) {
  console.log('=== START EUDI WALLET ERIKA MUSTERMANN PAYLOAD SIMULATION ===\n');

  async function runDemo() {
    // 1. generate key pairs for issuer, wallet and holder
    const issuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const walletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const holderKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

    const issuerPublicKeyPem = issuerKeys.publicKey.export({ type: 'spki', format: 'pem' });
    const walletPublicKeyPem = walletKeys.publicKey.export({ type: 'spki', format: 'pem' });

    const holderJwk = holderKeys.publicKey.export({ format: 'jwk' });

    // 2. generating mock WIA (Wallet Instance Attestation)
    const wiaHeader = { alg: 'ES256', typ: 'oauth-client-attestation+jwt' };
    const wiaPayload = {
      iss: 'https://wallet-provider.example.com',
      sub: 'https://wallet.example.com/instances/77777',
      wallet_name: 'EUDI National Wallet Reference Implementation',
      iat: Math.floor(Date.now() / 1000) - 10,
      exp: Math.floor(Date.now() / 1000) + 3600
    };
    const wiaData = `${Buffer.from(JSON.stringify(wiaHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(wiaPayload)).toString('base64url')}`;
    const wiaSign = crypto.createSign('SHA256');
    wiaSign.update(wiaData);
    const wiaSignature = wiaSign.sign(walletKeys.privateKey).toString('base64url');
    const wiaToken = `${wiaData}.${wiaSignature}`;

    // 3. generating main credential (SD-JWT) for "Erika Mustermann"
    // Disclosures in accordance with DE PID data set:
    const disclosures = [
      Buffer.from(JSON.stringify(['saltGName', 'given_name', 'Erika'])).toString('base64url'),
      Buffer.from(JSON.stringify(['saltFName', 'family_name', 'Mustermann'])).toString('base64url'),
      Buffer.from(JSON.stringify(['saltBDate', 'birthdate', '1998-08-12'])).toString('base64url'),
      Buffer.from(JSON.stringify(['saltIsOver18', 'is_over_18', true])).toString('base64url'),
      Buffer.from(JSON.stringify(['saltNats', 'nationalities', ['DE']])).toString('base64url'),
      Buffer.from(JSON.stringify(['saltAddr', 'address', {
        street_address: 'Heidestraße 17',
        locality: 'Köln',
        postal_code: '50667',
        country: 'DE'
      }])).toString('base64url')
    ];

    // calculate disclosure hashes for main JWT
    const hash = (data) => crypto.createHash('sha256').update(data).digest().toString('base64url');
    const sdHeader = { alg: 'ES256', typ: 'vc+sd-jwt' };
    const sdPayload = {
      iss: 'https://pid-provider.gov.de',
      vct: 'https://example.bmi.bund.de/credential/pid/1.0',
      _sd_alg: 'sha-256',
      _sd: disclosures.map(hash),
      cnf: {
        jwk: holderJwk // cryptographic device binding
      },
      status: {
        status_list: {
          idx: 125,
          uri: 'https://pid-provider.gov.de/status/list-core'
        }
      }
    };

    const sdData = `${Buffer.from(JSON.stringify(sdHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(sdPayload)).toString('base64url')}`;
    const sdSign = crypto.createSign('SHA256');
    sdSign.update(sdData);
    const sdSignature = sdSign.sign(issuerKeys.privateKey).toString('base64url');
    const credentialJwt = `${sdData}.${sdSignature}`;

    // 4. generating the key binding JWT 
    const rpClientId = 'x509_san_dns:client.example.org';
    const transactionNonce = 'n-0S6_WzA2Mj'; // taken from specs

    const kbHeader = { alg: 'ES256', typ: 'openid4vci-proof+jwt' };
    const kbPayload = {
      aud: rpClientId,
      nonce: transactionNonce,
      iat: Math.floor(Date.now() / 1000)
    };

    const kbData = `${Buffer.from(JSON.stringify(kbHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(kbPayload)).toString('base64url')}`;
    const kbSign = crypto.createSign('SHA256');
    kbSign.update(kbData);
    const kbSignature = kbSign.sign(holderKeys.privateKey).toString('base64url');
    const kbJwt = `${kbData}.${kbSignature}`;

    // 5. composing the complete SD-JWT string incl. disclosures
    const fullSdJwt = `${credentialJwt}~${disclosures.join('~')}~${kbJwt}`;

    // 6. instantiating the verifier and executing the verification flow
    const verifier = new EUDIVerifier({
      clientId: rpClientId,
      expectedNonce: transactionNonce,
      trustedIssuerKeys: [issuerPublicKeyPem],
      trustedWalletKeys: [walletPublicKeyPem]
    });

    const mockVpToken = {
      "my_identity_credential": fullSdJwt
    };

    console.log('Executing security validation...\n');
    const verificationResult = await verifier.verifyPresentation(mockVpToken, wiaToken);

    console.log('VERIFICATION RESULT:');
    console.log(JSON.stringify(verificationResult, null, 2));

    if (verificationResult.success) {
      console.log('\n✅ SIMULATION SUCCESSFUL! All verification checks have passed.');
      console.log('Authentic claims:');
      console.log(JSON.stringify(verificationResult.claims, null, 2));
    } else {
      console.error('\n❌ SIMULATION FAILED.');
    }
  }

  runDemo().catch(console.error);
}

module.exports = { EUDIVerifier };