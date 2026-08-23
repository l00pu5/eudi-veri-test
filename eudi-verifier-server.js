/**
 * EUDI Wallet - Combined Relying Party (RP) & Credential Issuer REST API Server
 * 
 * This module implemented endpoints for:
 * 1. RP backend for credential presentation (OpenID4VP)
 * 2. Issuer backend for issuing mock PID (OpenID4VCI / HAIP)
 */

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const { EUDIVerifier } = require('./eudi-verifier-helper');
const { EUDIPIDIssuerVerifier } = require('./eudi-issuer-verifier');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware coniguration
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// session management for saving nonce and verification results
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 300000 } // default validity period: 5min
}));

// in-memory store for transient status sync (production: use Redis)
const transactionStore = new Map();
const accessTokenStore = new Map(); // token -> { dpopKey, claims }

// RP configuration
const RP_CONFIG = {
  clientId: 'x509_san_dns:client.example.org',
  publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
  trustedIssuerKeys: [],
  trustedWalletKeys: []
};

// credential issuer configuration
const ISSUER_CONFIG = {
  issuerId: process.env.ISSUER_ID || `http://localhost:${PORT}/api/issuance`, // dynamic IssuerId matching server host
  publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
  trustedWalletKeys: []
};

// generate cryptographic keys for demo purposes (simulates trust store / PKI)
let demoIssuerKeys, demoWalletKeys, rpSigningKeys;
try {
  demoIssuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  demoWalletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  rpSigningKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); // JAR signing

  // populate trust store
  RP_CONFIG.trustedIssuerKeys.push(demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  RP_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  ISSUER_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));
} catch (e) {
  console.error('Error while generating keys:', e);
}

// instantiating PID provider (issuer)
const pidIssuer = new EUDIPIDIssuerVerifier({
  issuerId: ISSUER_CONFIG.issuerId,
  issuerPrivateKeyPem: demoIssuerKeys.privateKey.export({ type: 'sec1', format: 'pem' }),
  issuerPublicKeyPem: demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }),
  trustedWalletKeys: ISSUER_CONFIG.trustedWalletKeys
});

// =============================================================================
// PART 1: SPREAD ENDPOINTS FOR PRESENTATION SCNEARIO (OPENID4VP)
// =============================================================================

// INITIATE PRESENTATION (generate QR code content)
app.get('/api/presentation/initiate', (req, res) => {
  const sessionId = 'session_' + crypto.randomBytes(12).toString('hex');
  const nonce = 'nonce_' + crypto.randomBytes(16).toString('hex');

  req.session.sessionId = sessionId;
  req.session.expectedNonce = nonce;
  req.session.verificationStatus = 'PENDING';

  transactionStore.set(sessionId, {
    type: 'PRESENTATION',
    nonce: nonce,
    status: 'PENDING',
    claims: null,
    errors: [],
    responseCode: null
  });

  const requestUri = `${RP_CONFIG.publicUrl}/api/presentation/request-jwt?sid=${sessionId}`;
  const qrCodeUrl = `openid4vp://?client_id=${encodeURIComponent(RP_CONFIG.clientId)}&request_uri=${encodeURIComponent(requestUri)}`;

  console.log(`[RP Server] Session initated. ID: ${sessionId}, expected nonce: ${nonce}`);

  res.json({
    success: true,
    sessionId: sessionId,
    qrCodeUrl: qrCodeUrl,
    pollEndpoint: `/api/presentation/status?sid=${sessionId}`
  });
});

// PROVIDE REQUEST OBJECT (JAR)
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
    response_mode: "direct_post",
    response_uri: `${RP_CONFIG.publicUrl}/api/presentation/callback`,
    client_id: RP_CONFIG.clientId,
    nonce: tx.nonce,
    state: sessionId,
    dcql_query: dcqlQuery
  };

  const jwtHeader = {
    alg: 'ES256',
    typ: 'oauth-authz-req+jwt'
  };

  try {
    const tokenInput = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(requestPayload)).toString('base64url')}`;
    const signer = crypto.createSign('SHA256');
    signer.update(tokenInput);
    const signature = signer.sign(rpSigningKeys.privateKey, 'base64url');
    const signedJwt = `${tokenInput}.${signature}`;

    console.log(`[RP Server] JAR request for session ${sessionId} delivered to wallet.`);

    res.setHeader('Content-Type', 'application/oauth-authz-req+jwt');
    res.setHeader('Cache-Control', 'no-store');
    res.send(signedJwt);
  } catch (err) {
    console.error('JAR signing error:', err);
    res.status(500).json({ error: 'Server error while generating JAR' });
  }
});

// DIRECT_POST CALLBACK
app.post('/api/presentation/callback', async (req, res) => {
  const { vp_token, state, wia_token } = req.body;

  console.log(`[RP Server] direct_post callback received. State (session ID): ${state}`);

  if (!state || !transactionStore.has(state)) {
    return res.status(400).json({ error: 'Transaction context missing or expired' });
  }

  const tx = transactionStore.get(state);

  try {
    let parsedVpToken;
    try {
      parsedVpToken = JSON.parse(vp_token);
    } catch (e) {
      parsedVpToken = JSON.parse(decodeURIComponent(vp_token));
    }

    const verifier = new EUDIVerifier({
      clientId: RP_CONFIG.clientId,
      expectedNonce: tx.nonce,
      trustedIssuerKeys: RP_CONFIG.trustedIssuerKeys,
      trustedWalletKeys: RP_CONFIG.trustedWalletKeys
    });

    console.log(`[RP Server] Initiating verification for session: ${state}...`);
    const verificationResult = await verifier.verifyPresentation(parsedVpToken, wia_token);

    if (verificationResult.success) {
      console.log(`[RP Server] ✅ Verification succcessful! Claims for ${state} have been extracted.`);

      const responseCode = crypto.randomBytes(16).toString('hex');
      tx.status = 'SUCCESS';
      tx.claims = verificationResult.claims;
      tx.responseCode = responseCode;
      transactionStore.set(state, tx);

      res.status(200).json({
        redirect_uri: `${RP_CONFIG.publicUrl}/login-success.html?sid=${state}&code=${responseCode}`
      });
    } else {
      console.error(`[RP Server] ❌ Verification failed:`, verificationResult.errors);
      tx.status = 'FAILED';
      tx.errors = verificationResult.errors;
      transactionStore.set(state, tx);

      res.status(400).json({ error: 'Crytographic verification has failed.' });
    }
  } catch (err) {
    console.error('Internal direct_post error:', err);
    tx.status = 'FAILED';
    tx.errors.push(err.message);
    transactionStore.set(state, tx);
    res.status(500).json({ error: 'Internal server error in direct_post callback' });
  }
});

// STATUS POLLING FOR FRONTEND
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
      responseCode: tx.responseCode
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
// PART 2: ENDPOINTS FOR ISSUANCE & VALIDATION (OPENID4VCI)
// =============================================================================

// ISSUANCE 1: INITIATION (returns a credential offer)
app.get('/api/issuance/initiate', (req, res) => {
  const sessionId = 'session_iss_' + crypto.randomBytes(12).toString('hex');
  const wiaChallenge = 'challenge_iss_' + crypto.randomBytes(16).toString('hex');

  // In-Memory registrieren
  transactionStore.set(sessionId, {
    type: 'ISSUANCE',
    wiaChallenge: wiaChallenge,
    status: 'PENDING'
  });

  const issuerUrl = `${ISSUER_CONFIG.publicUrl}/api/issuance`;
  const offerObj = {
    credential_issuer: issuerUrl,
    credential_configuration_ids: ['PID_SD_JWT_VC'],
    grants: {
      authorization_code: {
        issuer_state: sessionId
      }
    }
  };

  const offerUrl = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offerObj))}`;
  const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(offerUrl)}`;

  console.log(`[Issuer Server] Issuance session initiated. Challenge: ${wiaChallenge}`);

  res.json({
    success: true,
    sessionId: sessionId,
    wiaChallenge: wiaChallenge,
    credentialOfferUrl: offerUrl,
    qrCodeUrl: qrCodeUrl
  });
});

// ISSUANCE 2: WELL-KNOWN METADATA
app.get('/api/issuance/.well-known/openid-credential-issuer', (req, res) => {
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
      }
    }
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json(metadata);
});

// ISSUANCE 3: NONCE ENDPOINT
app.post('/api/issuance/nonce', (req, res) => {
  console.log('[Issuer Server] Nonce request received.');
  const nonces = pidIssuer.generateNonceResponse();
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json(nonces);
});

// ISSUANCE 4: TOKEN ENDPOINT (DPoP  & WIA verification)
app.post('/api/issuance/token', (req, res) => {
  console.log('[Issuer Server] Token request received.');

  const { code, code_verifier, client_assertion, client_assertion_pop, wia_challenge_sid } = req.body;
  const dpopProof = req.headers['dpop'];

  let expectedWiaChallenge = null;
  if (wia_challenge_sid && transactionStore.has(wia_challenge_sid)) {
    expectedWiaChallenge = transactionStore.get(wia_challenge_sid).wiaChallenge;
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
    console.log('[Issuer Server] ✅ Token request successfully validated. Generating access token...');

    const accessToken = 'access_token_' + crypto.randomBytes(16).toString('hex');
    const nonceResponse = pidIssuer.generateNonceResponse();

    // saving token context for credential endpoint query
    accessTokenStore.set(accessToken, {
      dpopKey: tokenResult.dpopKey,
      scope: 'PID_SD_JWT_VC'
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
    console.error('[Issuer Server] ❌ Token verifikation failed:', tokenResult.errors);
    res.status(400).json({
      error: 'invalid_request',
      error_description: tokenResult.errors.join(', ')
    });
  }
});

// ISSUANCE 5: CREDENTIAL ENDPOINT (issuance & issuance validation)
app.post('/api/issuance/credential', (req, res) => {
  console.log('[Issuer Server] Credential request received.');

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('DPoP ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'DPoP access token required in authorization header.'
    });
  }
  const accessToken = authHeader.substring(5);
  const tokenData = accessTokenStore.get(accessToken);

  if (!tokenData) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Access token is invalid, expired or unknown.'
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
    console.log('[Issuer Server] ✅ Credential ownership verification successful. Generating SD-JWT VC...');

    // Erika Mustermann PID data set
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

    const signedPid = pidIssuer.issuePID({
      claims: erikaClaims,
      holderJwk: credResult.devicePublicKeyJwk
    });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      credentials: [
        {
          credential: signedPid
        }
      ]
    });
  } else {
    console.error('[Issuer Server] ❌ Credential ownership verification failed:', credResult.errors);
    res.status(400).json({
      error: 'invalid_proof',
      error_description: credResult.errors.join(', ')
    });
  }
});

// start API server
app.listen(PORT, () => {
  console.log(`\n=== EUDI WALLET INTEGRATED SERVER (PRESENTATION & ISSUANCE) ===`);
  console.log(`Server running locally at: http://localhost:${PORT}`);
  console.log(`Public RP identity (client_id): ${RP_CONFIG.clientId}`);
  console.log(`Public issuer identity (issuer_id): ${ISSUER_CONFIG.issuerId}`);
  console.log(`Waitin for wallet connections (issuance or presentation)...\n`);
});

module.exports = app;