/**
 * EUDI Wallet - Relying Party (RP) & Credential Issuer REST API Server
 * 
 * This module implements the endpoints for:
 * 1. RP backend for credential presentation (OpenID4VP) with JWE decrypton (direct_post.jwt)
 * 2. Issuer backend for issuing a sample PID (OpenID4VCI / HAIP)
 * 
 * It uses the verifier module 'eudi-verifier-helper_demo.js' (RP)
 * and 'eudi-issuer-verifier.js' (Issuer).
 * 
 * It will save the demo keys that are automatically being generated on startup
 * to ./demo-keys.json to allw external test clients to verify the WIA cryptographically.
 * 
 * Installation of requirements:
 * npm install
 */

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const dotenv = require("dotenv");
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { EUDIVerifier } = require('./eudi-verifier-helper_demo');
const { EUDIPIDIssuerVerifier } = require('./eudi-issuer-verifier');

const app = express();
const PORT = process.env.PORT || 3000;

// read .env
dotenv.config();

// Middleware configuration
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// serve static files (e.g. index.html) from the current directory
app.use(express.static(__dirname));

// web UI / frontend (index.html)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// session management for saving nonce and verification results
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 300000 } // default validity: 5min
}));

// in-memory store for transient status verification (replace with Redis in production)
const transactionStore = new Map();
const accessTokenStore = new Map(); // token -> { dpopKey, claims }

// RP configuration
const RP_CONFIG = {
  clientId: 'x509_san_dns:client.example.org',
  publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
  trustedIssuerKeys: [],
  trustedWalletKeys: []
};

// Issuer configuration
const ISSUER_CONFIG = {
  issuerId: process.env.ISSUER_ID || `http://localhost:${PORT}/api/issuance`, // dynamic IssuerId matching with server host
  publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
  trustedWalletKeys: []
};

// cryptographic keys for demo operations (simulates trust store / PKI)
let demoIssuerKeys, demoWalletKeys, rpSigningKeys;
let rpSigningCertBase64 = "";

try {
  const { execSync } = require('child_process');
  if (!fs.existsSync('./rp-private-key.pem')) {
    const cnfContent = `[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = v3_req\nx509_extensions = v3_req\nprompt = no\n\n[req_distinguished_name]\nCN = client.example.org\n\n[v3_req]\nkeyUsage = nonRepudiation, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = DNS:client.example.org`;
    fs.writeFileSync('./openssl.cnf', cnfContent);
    execSync("openssl ecparam -name prime256v1 -genkey -noout -out ./rp-private-key.pem");
    execSync("openssl req -new -x509 -key ./rp-private-key.pem -out ./rp-cert.pem -days 365 -config ./openssl.cnf");
  }
  const privPem = fs.readFileSync('./rp-private-key.pem', 'utf8');
  const certPem = fs.readFileSync('./rp-cert.pem', 'utf8');
  rpSigningKeys = {
    privateKey: crypto.createPrivateKey(privPem),
    publicKey: crypto.createPublicKey(certPem)
  };
  rpSigningCertBase64 = certPem
    .replace(/-----\s*(BEGIN|END)\s+CERTIFICATE\s*-----/g, '')
    .replace(/[\r\n]/g, '');
  console.log('[Server Setup] RP signing certificate has been loaded; x5c value has been extracted.');
} catch (err) {
  console.error('Error while loading RP keys or cert:', err);
  rpSigningKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

try {
  demoIssuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  demoWalletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  // fill simulated trust stores
  RP_CONFIG.trustedIssuerKeys.push(demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  RP_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  ISSUER_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));

  // saving dynamically generated demo keys in JSON file to allow OpenID4VCI test client to generate correct WIA signature
  fs.writeFileSync('./demo-keys.json', JSON.stringify({
    demoWalletKeys: {
      privateKey: demoWalletKeys.privateKey.export({ type: 'sec1', format: 'pem' }),
      publicKey: demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' })
    },
    demoIssuerKeys: {
      privateKey: demoIssuerKeys.privateKey.export({ type: 'sec1', format: 'pem' }),
      publicKey: demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' })
    }
  }, null, 2));
  console.log('[Server Setup] demo keys successfully exported to ./demo-keys.json.');
} catch (e) {
  console.error('Error while generating demo keys:', e);
}

// Instantiating the PID provider (Issuer)
const pidIssuer = new EUDIPIDIssuerVerifier({
  issuerId: ISSUER_CONFIG.issuerId,
  issuerPrivateKeyPem: demoIssuerKeys.privateKey.export({ type: 'sec1', format: 'pem' }),
  issuerPublicKeyPem: demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }),
  trustedWalletKeys: ISSUER_CONFIG.trustedWalletKeys
});

// ─────────────────────────────────────────────────────────────────────────────
// LIGHTWEIGHT CBOR CODEC (RFC 8949)
// ─────────────────────────────────────────────────────────────────────────────

function encodeTypeAndLength(type, length) {
  const major = type << 5;
  if (length < 24) {
    return Buffer.from([major | length]);
  } else if (length < 0x100) {
    return Buffer.from([major | 24, length]);
  } else if (length < 0x10000) {
    const buf = Buffer.alloc(3);
    buf[0] = major | 25;
    buf.writeUInt16BE(length, 1);
    return buf;
  } else {
    const buf = Buffer.alloc(5);
    buf[0] = major | 26;
    buf.writeUInt32BE(length, 1);
    return buf;
  }
}

function encodeCBOR(val) {
  if (val === null) {
    return Buffer.from([0xf6]);
  }
  if (val === undefined) {
    return Buffer.from([0xf7]);
  }
  if (typeof val === 'boolean') {
    return Buffer.from([val ? 0xf5 : 0xf4]);
  }
  if (typeof val === 'number') {
    if (Number.isInteger(val)) {
      if (val >= 0) {
        return encodeTypeAndLength(0, val);
      } else {
        return encodeTypeAndLength(1, -val - 1);
      }
    } else {
      throw new Error("Floating point numbers not supported on this layer.");
    }
  }
  if (typeof val === 'string') {
    const buf = Buffer.from(val, 'utf8');
    return Buffer.concat([encodeTypeAndLength(3, buf.length), buf]);
  }
  if (Buffer.isBuffer(val)) {
    return Buffer.concat([encodeTypeAndLength(2, val.length), val]);
  }
  if (Array.isArray(val)) {
    const encodedElements = val.map(encodeCBOR);
    return Buffer.concat([encodeTypeAndLength(4, val.length), ...encodedElements]);
  }
  if (typeof val === 'object') {
    const keys = Object.keys(val);
    const encodedPairs = [];
    for (const k of keys) {
      encodedPairs.push(encodeCBOR(k));
      encodedPairs.push(encodeCBOR(val[k]));
    }
    return Buffer.concat([encodeTypeAndLength(5, keys.length), ...encodedPairs]);
  }
  throw new Error("Unsupported CBOR data type: " + typeof val);
}

function base64url(strOrBuffer) {
  const buffer = Buffer.isBuffer(strOrBuffer) ? strOrBuffer : Buffer.from(strOrBuffer);
  return buffer.toString('base64url');
}


function decryptJweResponse(jweString, privateKeyPem) {
  const parts = jweString.split('.');
  if (parts.length !== 5) {
    throw new Error('Invalid JWE compact format. Expected: 5 segments.');
  }

  const [protectedHeaderB64, encryptedKeyB64, ivB64, ciphertextB64, tagB64] = parts;

  const header = JSON.parse(Buffer.from(protectedHeaderB64, 'base64url').toString('utf8'));
  if (header.alg !== 'ECDH-ES') {
    throw new Error(`Unsupported JWE algorithm: ${header.alg}`);
  }
  if (header.enc !== 'A128GCM' && header.enc !== 'A256GCM') {
    throw new Error(`Unsupported symmetric encryption: ${header.enc}`);
  }
  if (!header.epk) {
    throw new Error('Ephemeral Public Key (epk) missing in JWE header.');
  }

  const walletEphemeralPublicKey = crypto.createPublicKey({
    key: header.epk,
    format: 'jwk'
  });

  const rpPrivateKey = crypto.createPrivateKey(privateKeyPem);

  const sharedSecret = crypto.diffieHellman({
    privateKey: rpPrivateKey,
    publicKey: walletEphemeralPublicKey
  });

  const keyLengthBytes = header.enc === 'A128GCM' ? 16 : 32;
  const cek = deriveConcatKDF(
    sharedSecret,
    keyLengthBytes,
    header.enc,
    header.apu,
    header.apv
  );

  const iv = Buffer.from(ivB64, 'base64url');
  const ciphertext = Buffer.from(ciphertextB64, 'base64url');
  const tag = Buffer.from(tagB64, 'base64url');
  const aad = Buffer.from(protectedHeaderB64, 'ascii');

  const decipher = crypto.createDecipheriv(
    header.enc === 'A128GCM' ? 'aes-128-gcm' : 'aes-256-gcm',
    cek,
    iv
  );

  decipher.setAAD(aad);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return JSON.parse(decrypted.toString('utf8'));
}

// =============================================================================
// PART 1: PRESENTATION ENDPOINTS (OPENID4VP)
// =============================================================================

app.get('/api/presentation/initiate', (req, res) => {
  const sessionId = 'session_' + crypto.randomBytes(12).toString('hex');
  const nonce = 'nonce_' + crypto.randomBytes(16).toString('hex');

  let privateKeyPem, publicKeyJwk;
  try {
    const encKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    privateKeyPem = encKeyPair.privateKey.export({ type: 'sec1', format: 'pem' });
    publicKeyJwk = encKeyPair.publicKey.export({ format: 'jwk' });
  } catch (e) {
    console.error('Error while generated key pair for JWE:', e);
  }

  req.session.sessionId = sessionId;
  req.session.expectedNonce = nonce;
  req.session.verificationStatus = 'PENDING';

  transactionStore.set(sessionId, {
    type: 'PRESENTATION',
    nonce: nonce,
    status: 'PENDING',
    claims: null,
    errors: [],
    responseCode: null,
    privateKeyPem: privateKeyPem,
    publicKeyJwk: publicKeyJwk
  });

  const requestUri = `${RP_CONFIG.publicUrl}/api/presentation/request-jwt?sid=${sessionId}`;
  const qrCodeUrl = `openid4vp://?client_id=${encodeURIComponent(RP_CONFIG.clientId)}&request_uri=${encodeURIComponent(requestUri)}`;

  console.log(`[RP Server] Session Initiated. ID: ${sessionId}, expected nonce: ${nonce}`);

  res.json({
    success: true,
    sessionId: sessionId,
    qrCodeUrl: qrCodeUrl,
    pollEndpoint: `/api/presentation/status?sid=${sessionId}`
  });
});

app.get('/api/presentation/request-jwt', (req, res) => {
  const sessionId = req.query.sid;

  if (!sessionId || !transactionStore.has(sessionId)) {
    return res.status(400).json({ error: 'Invalid or expired transaction ID' });
  }

  const tx = transactionStore.get(sessionId);

  const dcqlQuery = {
    credentials: [
      {
        id: "my_identity_credential",
        format: "dc+sd-jwt",
        meta: {
          vct_values: ["https://credentials.example.com/identity_credential"]
        },
        claims: [
          { "path": ["given_name"] },
          { "path": ["family_name"] },
          { "path": ["birthdate"] },
          { "path": ["is_over_18"] },
          { "path": ["address"] }
        ]
      }
    ]
  };

  const requestPayload = {
    iss: RP_CONFIG.clientId,
    aud: "https://self-issued.me/v2",
    response_type: "vp_token",
    response_mode: "direct_post.jwt",
    response_uri: `${RP_CONFIG.publicUrl}/api/presentation/callback`,
    client_id: RP_CONFIG.clientId,
    nonce: tx.nonce,
    state: sessionId,
    dcql_query: dcqlQuery,
    client_metadata: {
      jwks: {
        keys: [
          {
            ...tx.publicKeyJwk,
            kid: "enc-key-1",
            use: "enc",
            alg: "ECDH-ES"
          }
        ]
      },
      encrypted_response_enc_values_supported: ["A128GCM", "A256GCM"]
    }
  };

  const jwtHeader = {
    alg: 'ES256',
    typ: 'oauth-authz-req+jwt'
  };
  if (rpSigningCertBase64) {
    jwtHeader.x5c = [rpSigningCertBase64];
  }

  try {
    const tokenInput = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(requestPayload)).toString('base64url')}`;
    const signer = crypto.createSign('SHA256');
    signer.update(tokenInput);
    const signature = signer.sign(rpSigningKeys.privateKey, 'base64url');
    const signedJwt = `${tokenInput}.${signature}`;

    console.log(`[RP Server] JAR request for session ${sessionId} has been delivered to wallet.`);

    res.setHeader('Content-Type', 'application/oauth-authz-req+jwt');
    res.setHeader('Cache-Control', 'no-store');
    res.send(signedJwt);
  } catch (err) {
    console.error('JAR Signierungsfehler:', err);
    res.status(500).json({ error: 'Cryptographic server error while generating JAR' });
  }
});

app.post('/api/presentation/callback', async (req, res) => {
  let { vp_token, state, wia_token, response } = req.body;

  console.log(`[RP Server] direct_post callback received.`);

  let isEncrypted = false;
  let decryptedPayload = null;
  let decryptionError = null;

  let tokenToDecrypt = response || (typeof req.body === 'string' ? req.body : null);

  if (!tokenToDecrypt && req.body && typeof req.body === 'object') {
    const keys = Object.keys(req.body);
    if (keys.length === 1 && typeof keys[0] === 'string' && keys[0].split('.').length === 5) {
      tokenToDecrypt = keys[0];
    }
  }

  if (tokenToDecrypt && typeof tokenToDecrypt === 'string' && tokenToDecrypt.split('.').length === 5) {
    isEncrypted = true;
    console.log('[RP Server] Cryptographic JWE envelope detected. Initiating decryption (direct_post.jwt)...');

    let assumedState = state || req.query.sid || req.query.state;

    if (assumedState && transactionStore.has(assumedState)) {
      const tx = transactionStore.get(assumedState);
      if (tx.privateKeyPem) {
        try {
          decryptedPayload = decryptJweResponse(tokenToDecrypt, tx.privateKeyPem);
          state = assumedState;
          console.log(`[RP Server] JWE decrypted successfully with key of session: ${state}`);
        } catch (err) {
          decryptionError = err;
          console.warn(`[RP Server] direct encryption failed:`, err.message);
        }
      }
    }

    if (!decryptedPayload) {
      console.log('[RP Server] searching pending transacions for matching key...');
      for (const [txId, tx] of transactionStore.entries()) {
        if (tx.status === 'PENDING' && tx.privateKeyPem) {
          try {
            decryptedPayload = decryptJweResponse(tokenToDecrypt, tx.privateKeyPem);
            state = txId;
            console.log(`[RP Server] JWE decrypted successfully! Linked to session: ${state}`);
            break;
          } catch (err) {
            // try keys
          }
        }
      }
    }

    if (decryptedPayload) {
      vp_token = decryptedPayload.vp_token;
      wia_token = decryptedPayload.wia_token || wia_token;
    } else {
      console.error('[RP Server] ❌ JWE decryption has failed. No matching session ID found.');
      return res.status(400).json({
        error: 'decryption_failed',
        error_description: decryptionError ? decryptionError.message : 'Payload could not be decoded with any active session key.'
      });
    }
  }

  console.log(`[RP Server] Callback session (state): ${state}`);

  if (!state || !transactionStore.has(state)) {
    return res.status(400).json({ error: 'Transaction context missing or expired' });
  }

  const tx = transactionStore.get(state);

  try {
    let parsedVpToken;
    if (typeof vp_token === 'string') {
      try {
        parsedVpToken = JSON.parse(vp_token);
      } catch (e) {
        parsedVpToken = JSON.parse(decodeURIComponent(vp_token));
      }
    } else {
      parsedVpToken = vp_token;
    }

    const verifier = new EUDIVerifier({
      clientId: RP_CONFIG.clientId,
      expectedNonce: tx.nonce,
      trustedIssuerKeys: RP_CONFIG.trustedIssuerKeys,
      trustedWalletKeys: RP_CONFIG.trustedWalletKeys
    });

    console.log(`[RP Server] Starting session validation: ${state}...`);
    const verificationResult = await verifier.verifyPresentation(parsedVpToken, wia_token);

    if (verificationResult.success) {
      console.log(`[RP Server] ✅ Verification has been successful! ${verificationResult.format} format processed for ${state}.`);

      const responseCode = crypto.randomBytes(16).toString('hex');
      tx.status = 'SUCCESS';
      tx.claims = verificationResult.claims;
      tx.responseCode = responseCode;
      tx.isEncrypted = isEncrypted;
      tx.format = verificationResult.format; // format (SD-JWT VC or ISO mdoc)
      tx.integrityLog = verificationResult.integrityLog || [];
      tx.rawSdList = verificationResult.rawSdList || [];
      transactionStore.set(state, tx);

      res.status(200).json({
        redirect_uri: `${RP_CONFIG.publicUrl}/login-success.html?sid=${state}&code=${responseCode}`
      });
    } else {
      console.error(`[RP Server] ❌ Verification has failed:`, verificationResult.errors);
      tx.status = 'FAILED';
      tx.errors = verificationResult.errors;
      transactionStore.set(state, tx);

      res.status(400).json({ error: 'Cryptographic verification has failed.' });
    }
  } catch (err) {
    console.error('Internal direct_post error:', err);
    tx.status = 'FAILED';
    tx.errors.push(err.message);
    transactionStore.set(state, tx);
    res.status(500).json({ error: 'Internal server error in direct_post callback' });
  }
});

app.get('/api/presentation/status', (req, res) => {
  const sessionId = req.query.sid;

  if (!sessionId || !transactionStore.has(sessionId)) {
    return res.status(404).json({ success: false, status: 'NOT_FOUND', error: 'Invalid session' });
  }

  const tx = transactionStore.get(sessionId);

  if (tx.status === 'SUCCESS') {
    return res.json({
      success: true,
      status: 'SUCCESS',
      claims: tx.claims,
      responseCode: tx.responseCode,
      isEncrypted: tx.isEncrypted,
      format: tx.format, // indicates format to frontend
      integrityLog: tx.integrityLog || [],
      rawSdList: tx.rawSdList || []
    });
  } else if (tx.status === 'FAILED') {
    return res.json({
      success: false,
      status: 'FAILED',
      errors: tx.errors
    });
  }

  res.json({
    success: true,
    status: 'PENDING'
  });
});

// =============================================================================
// PART 2: ISSUANCE AND VALIDATION ENDPOINTS (OPENID4VCI)
// =============================================================================

app.get('/api/issuance/session-info', (req, res) => {
  const sessionId = req.query.sid;
  if (!sessionId || !transactionStore.has(sessionId)) {
    return res.status(404).json({ error: 'Session not found' });
  }
  const tx = transactionStore.get(sessionId);
  res.json({
    wiaChallenge: tx.wiaChallenge,
    claims: tx.claims,
    validityDays: tx.validityDays
  });
});

app.all('/api/issuance/initiate', (req, res) => {
  const sessionId = 'session_iss_' + crypto.randomBytes(12).toString('hex');
  const wiaChallenge = 'challenge_iss_' + crypto.randomBytes(16).toString('hex');

  let customClaims = null;
  let customValidityDays = 90;
  let format = 'dc+sd-jwt';

  if (req.method === 'POST') {
    const { claims, validityDays, format: reqFormat } = req.body;
    if (claims) {
      customClaims = claims;
    }
    if (validityDays) {
      customValidityDays = parseInt(validityDays, 10) || 90;
    }
    if (reqFormat) {
      format = reqFormat;
    }
  } else {
    const { format: reqFormat } = req.query;
    if (reqFormat) {
      format = reqFormat;
    }
  }

  transactionStore.set(sessionId, {
    type: 'ISSUANCE',
    wiaChallenge: wiaChallenge,
    status: 'PENDING',
    claims: customClaims,
    validityDays: customValidityDays,
    format: format
  });

  const issuerUrl = `${ISSUER_CONFIG.publicUrl}/api/issuance`;
  const offerObj = {
    credential_issuer: issuerUrl,
    credential_configuration_ids: format === 'mso_mdoc' ? ['mDL_mso_mdoc'] : ['PID_SD_JWT_VC'],
    grants: {
      authorization_code: {
        issuer_state: sessionId
      }
    }
  };

  const offerUrl = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offerObj))}`;
  const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(offerUrl)}`;

  console.log(`[Issuer Server] Issuance session initiated. ID: ${sessionId}, Challenge: ${wiaChallenge}, Validity: ${customValidityDays} days`);

  res.json({
    success: true,
    sessionId: sessionId,
    wiaChallenge: wiaChallenge,
    credentialOfferUrl: offerUrl,
    qrCodeUrl: qrCodeUrl
  });
});

app.get(['/api/issuance/.well-known/openid-credential-issuer', '/.well-known/openid-credential-issuer/api/issuance'], (req, res) => {
  const issuerUrl = `${ISSUER_CONFIG.publicUrl}/api/issuance`;
  const metadata = {
    credential_issuer: issuerUrl,
    authorization_servers: [`${ISSUER_CONFIG.publicUrl}/api/issuance`],
    credential_endpoint: `${issuerUrl}/credential`,
    nonce_endpoint: `${issuerUrl}/nonce`,
    credential_configurations_supported: {
      "PID_SD_JWT_VC": {
        format: "dc+sd-jwt",
        scope: "PID_SD_JWT_VC",
        credential_signing_alg_values_supported: ["ES256"],
        cryptographic_binding_methods_supported: ["jwk"],
        proof_types_supported: {
          "jwt": {
            "proof_signing_alg_values_supported": ["ES256"],
            "key_attestations_required": {
              "key_storage": ["iso_18045_moderate"],
              "user_authentication": ["iso_18045_moderate"]
            }
          }
        },
        vct: "https://credentials.example.com/identity_credential",
        credential_metadata: {
          display: [
            {
              name: "Muster Personenidentifikationsnachweis (PID)",
              locale: "de-DE",
              background_color: "#0B192C",
              text_color: "#FFFFFF"
            }
          ]
        }
      },
      "mDL_mso_mdoc": {
        format: "mso_mdoc",
        scope: "mDL_mso_mdoc",
        doctype: "org.iso.18013.5.1.mDL",
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: {
          "jwt": {
            "proof_signing_alg_values_supported": ["ES256"]
          }
        },
        credential_metadata: {
          display: [
            {
              name: "Muster EUDI Mobile Driving Licence (mDL)",
              locale: "de-DE",
              background_color: "#EC4899",
              text_color: "#FFFFFF"
            }
          ]
        }
      }
    }
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json(metadata);
});

app.post('/api/issuance/nonce', (req, res) => {
  console.log('[Issuer Server] Nonce request received.');
  const nonces = pidIssuer.generateNonceResponse();
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json(nonces);
});

app.post('/api/issuance/token', (req, res) => {
  console.log('[Issuer Server] Token request received.');

  const { code, code_verifier, client_assertion, client_assertion_pop, wia_challenge_sid } = req.body;
  const dpopProof = req.headers['dpop'];

  let expectedWiaChallenge = null;
  let storedClaims = null;
  let storedValidityDays = 90;
  let storedSid = null;
  let storedFormat = 'dc+sd-jwt';

  if (wia_challenge_sid && transactionStore.has(wia_challenge_sid)) {
    const tx = transactionStore.get(wia_challenge_sid);
    expectedWiaChallenge = tx.wiaChallenge;
    storedClaims = tx.claims;
    storedValidityDays = tx.validityDays;
    storedSid = wia_challenge_sid;
    storedFormat = tx.format || 'dc+sd-jwt';
  }

  const tokenResult = pidIssuer.verifyTokenRequest({
    code: code,
    codeVerifier: code_verifier,
    dpopProof: dpopProof,
    wiaToken: client_assertion,
    wiaPop: client_assertion_pop,
    expectedWiaChallenge: expectedWiaChallenge
  });

  if (tokenResult.success) {
    console.log('[Issuer Server] ✅ Token request has been verified successfully. Generating access token...');

    const accessToken = 'access_token_' + crypto.randomBytes(16).toString('hex');
    const nonceResponse = pidIssuer.generateNonceResponse();

    accessTokenStore.set(accessToken, {
      dpopKey: tokenResult.dpopKey,
      scope: storedFormat === 'mso_mdoc' ? 'mDL_mso_mdoc' : 'PID_SD_JWT_VC',
      claims: storedClaims,
      validityDays: storedValidityDays,
      sid: storedSid,
      format: storedFormat
    });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      access_token: accessToken,
      token_type: 'DPoP',
      expires_in: 3600,
      c_nonce: nonceResponse.c_nonce,
      c_nonce_expires_in: nonceResponse.c_nonce_expires_in
    });
  } else {
    console.error('[Issuer Server] ❌ Token verification failed:', tokenResult.errors);
    res.status(400).json({
      error: 'invalid_request',
      error_description: tokenResult.errors.join(', ')
    });
  }
});

app.post('/api/issuance/credential', (req, res) => {
  console.log('[Issuer Server] Credential request received.');

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('DPoP ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'DPoP access token rewquired in authorization header.'
    });
  }
  const accessToken = authHeader.substring(5);
  const tokenData = accessTokenStore.get(accessToken);

  if (!tokenData) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid, expired or unknown access token.'
    });
  }

  const dpopProof = req.headers['dpop'];
  const credentialRequest = req.body;

  const credResult = pidIssuer.verifyCredentialRequest({
    credentialRequest: credentialRequest,
    dpopProof: dpopProof,
    accessTokenPayload: {
      cnf: { jwk: tokenData.dpopKey }
    }
  });

  if (credResult.success) {
    const format = tokenData.format || 'dc+sd-jwt';

    if (format === 'mso_mdoc') {
      console.log('[Issuer Server] ✅ Proof-of-possession verification successful. Generating ISO mdoc (mDL)...');

      const claims = tokenData.claims || {
        given_name: 'Erika',
        family_name: 'Mustermann',
        birth_date: '1998-08-12',
        driving_privileges: 'B',
        issuing_country: 'DE'
      };

      const validityDays = tokenData.validityDays || 3650; // Default: 10 years for mDL

      const issueDate = new Date().toISOString().split('T')[0];
      const expiryDate = new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

      const mdNameSpace = {
        "org.iso.18013.5.1": {
          given_name: claims.given_name || "Erika",
          family_name: claims.family_name || "Mustermann",
          birth_date: claims.birth_date || claims.birthdate || "1998-08-12",
          issue_date: issueDate,
          expiry_date: expiryDate,
          issuing_country: claims.issuing_country || claims.country || "DE",
          driving_privileges: claims.driving_privileges || "B"
        }
      };

      const document = {
        docType: "org.iso.18013.5.1.mDL",
        issuerSigned: {
          nameSpaces: mdNameSpace,
          issuerAuth: encodeCBOR({
            protected: Buffer.from("issuer_protected_headers"),
            unprotected: {},
            payload: Buffer.from("issuer_signed_mdl_payload"),
            signature: Buffer.from("simulated_government_issuer_signature")
          })
        },
        deviceSigned: {
          nameSpaces: {},
          deviceAuth: {
            deviceSignature: {
              protected: Buffer.from("device_protected_headers"),
              unprotected: {},
              payload: null,
              signature: Buffer.from("simulated_device_secure_element_signature")
            }
          }
        }
      };

      const deviceResponse = {
        version: "1.0",
        documents: [document],
        status: 0
      };

      const deviceResponseCbor = encodeCBOR(deviceResponse);
      const base64DeviceResponse = base64url(deviceResponseCbor);

      // Set session status to SUCCESS so polling in browser registers complete issuance
      if (tokenData.sid && transactionStore.has(tokenData.sid)) {
        const tx = transactionStore.get(tokenData.sid);
        tx.status = 'SUCCESS';
        transactionStore.set(tokenData.sid, tx);
        console.log(`[Issuer Server] ✅ Session ${tokenData.sid} Status = SUCCESS.`);
      }

      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.json({
        credentials: [
          {
            credential: base64DeviceResponse
          }
        ]
      });
    } else {
      console.log('[Issuer Server] ✅ Proof-of-possession verification successful. Generating SD-JWT VC...');

      const defaultClaims = {
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

      const finalClaims = tokenData.claims || defaultClaims;
      const validityDays = tokenData.validityDays || 90;

      const signedPid = pidIssuer.issuePID({
        claims: finalClaims,
        holderJwk: credResult.devicePublicKeyJwk,
        validityDays: validityDays
      });

      // Set session status to SUCCESS so polling in browser registers complete issuance
      if (tokenData.sid && transactionStore.has(tokenData.sid)) {
        const tx = transactionStore.get(tokenData.sid);
        tx.status = 'SUCCESS';
        transactionStore.set(tokenData.sid, tx);
        console.log(`[Issuer Server] ✅ Session ${tokenData.sid} status = SUCCESS.`);
      }

      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.json({
        credentials: [
          {
            credential: signedPid
          }
        ]
      });
    }
  } else {
    console.error('[Issuer Server] ❌ Proof-of-possession verification failed:', credResult.errors);
    res.status(400).json({
      error: 'invalid_proof',
      error_description: credResult.errors.join(', ')
    });
  }
});

// Starten des API-Servers
app.listen(PORT, () => {
  console.log(`\n=== EUDI WALLET INTEGRATED SERVER (PRESENTATION & ISSUANCE) ===`);
  console.log(`Server running at: http://localhost:${PORT}`);
  console.log(`Public RP identity (client_id): ${RP_CONFIG.clientId}`);
  console.log(`Public issuer identity (issuer_id): ${ISSUER_CONFIG.issuerId}`);
  console.log(`Waiting for wallet connections (presentation and issuance)...\n`);
});

module.exports = app;