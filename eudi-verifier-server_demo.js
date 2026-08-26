/**
 * EUDI Wallet - Combined Relying Party (RP) & Credential Issuer REST API Server v15
 * 
 * Dieses Express-Modul implementiert die vollständigen Endpunkte für:
 * 1. Ein RP-Backend zur Präsentation von Credentials (OpenID4VP) mit JWE-Entschlüsselung (direct_post.jwt)
 * 2. Ein Issuer-Backend zur Ausstellung einer Muster-PID (OpenID4VCI v1.0 / HAIP 1.0)
 * 
 * Es verwendet das Validierungsmodul 'eudi-verifier-helper-v7.js' (RP)
 * und 'eudi-issuer-verifier.js' (Issuer).
 * 
 * Sichert beim Startup die generierten Demo-Keys in ./demo-keys.json,
 * damit externe Test-Clients die WIA kryptografisch korrekt signieren können.
 * 
 * Installation der benötigten Pakete:
 * npm install express express-session body-parser cors
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

// Middleware konfigurieren
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Statische Dateien (wie index.html und andere Assets) aus dem aktuellen Verzeichnis servieren
app.use(express.static(__dirname));

// Route für das Haupt-Frontend (index.html) an der Server-Wurzel
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Session-Management zur Speicherung von Nonce und Verifizierungsergebnissen
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 300000 } // 5 Minuten Gültigkeit
}));

// In-Memory Speicher für transienten Status-Abgleich (Alternative zu Redis im Produktivbetrieb)
const transactionStore = new Map();
const accessTokenStore = new Map(); // token -> { dpopKey, claims }

// Konfiguration der Relying Party (Präsentation)
const RP_CONFIG = {
  clientId: 'x509_san_dns:client.example.org',
  publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`, // Dynamische Auflösung
  trustedIssuerKeys: [],
  trustedWalletKeys: []
};

// Konfiguration des Credential Issuers (Ausstellung)
const ISSUER_CONFIG = {
  issuerId: process.env.ISSUER_ID || `http://localhost:${PORT}/api/issuance`, // Dynamischer IssuerId passend zum Server-Host
  publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
  trustedWalletKeys: []
};

// Kryptografische Schlüssel für Demo-Betrieb generieren (simuliert Trust-Store / PKI)
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
  console.log('[Server Setup] RP-Signing-Zertifikat geladen und x5c-Wert extrahiert.');
} catch (err) {
  console.error('Fehler bei der RP-Schlüssel/Cert-Ladung:', err);
  rpSigningKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

try {
  demoIssuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  demoWalletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  // Trust-Stores befüllen
  RP_CONFIG.trustedIssuerKeys.push(demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  RP_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  ISSUER_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));

  // Sichern der dynamisch generierten Demo-Keys in einer JSON-Datei,
  // damit der OpenID4VCI-Test-Client die WIA-Signatur mathematisch korrekt erzeugen kann.
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
  console.log('[Server Setup] Demo-Keys erfolgreich nach ./demo-keys.json exportiert.');
} catch (e) {
  console.error('Fehler bei der Schlüsselgenerierung:', e);
}

// Instanziierung des EUDI PID Providers (Aussteller)
const pidIssuer = new EUDIPIDIssuerVerifier({
  issuerId: ISSUER_CONFIG.issuerId,
  issuerPrivateKeyPem: demoIssuerKeys.privateKey.export({ type: 'sec1', format: 'pem' }),
  issuerPublicKeyPem: demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }),
  trustedWalletKeys: ISSUER_CONFIG.trustedWalletKeys
});

// =============================================================================
// KRYPTOGRAFISCHE HILFSFUNKTIONEN FÜR JWE-ENTSCHLÜSSELUNG (ECDH-ES + A128GCM/A256GCM)
// =============================================================================

// ???

// ─────────────────────────────────────────────────────────────────────────────
// ABHÄNGIGKEITSFREIER LIGHTWEIGHT CBOR-CODEC (GEMÄß RFC 8949)
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
      throw new Error("Gleitkommazahlen werden in dieser Krypto-Ebene nicht unterstützt.");
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
  throw new Error("Nicht unterstützter CBOR-Datentyp: " + typeof val);
}

function base64url(strOrBuffer) {
  const buffer = Buffer.isBuffer(strOrBuffer) ? strOrBuffer : Buffer.from(strOrBuffer);
  return buffer.toString('base64url');
}


function decryptJweResponse(jweString, privateKeyPem) {
  const parts = jweString.split('.');
  if (parts.length !== 5) {
    throw new Error('Ungültiges JWE-Kompaktformat. Erwartet werden 5 Segmente.');
  }

  const [protectedHeaderB64, encryptedKeyB64, ivB64, ciphertextB64, tagB64] = parts;

  const header = JSON.parse(Buffer.from(protectedHeaderB64, 'base64url').toString('utf8'));
  if (header.alg !== 'ECDH-ES') {
    throw new Error(`Nicht unterstützter JWE-Algorithmus: ${header.alg}`);
  }
  if (header.enc !== 'A128GCM' && header.enc !== 'A256GCM') {
    throw new Error(`Nicht unterstützte symmetrische Verschlüsselung: ${header.enc}`);
  }
  if (!header.epk) {
    throw new Error('Ephemeral Public Key (epk) fehlt im JWE-Header.');
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
// TEIL 1: SPREAD-ENDPOINTS FÜR PRÄSENTATION (OPENID4VP)
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
    console.error('Fehler bei der Keypair-Generierung für JWE:', e);
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

  console.log(`[RP Server] Session initiiert. ID: ${sessionId}, Erwartete Nonce: ${nonce}`);

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
    return res.status(400).json({ error: 'Ungültige oder abgelaufene Transaktions-ID' });
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

    console.log(`[RP Server] JAR-Request für Session ${sessionId} an Wallet ausgeliefert.`);

    res.setHeader('Content-Type', 'application/oauth-authz-req+jwt');
    res.setHeader('Cache-Control', 'no-store');
    res.send(signedJwt);
  } catch (err) {
    console.error('JAR Signierungsfehler:', err);
    res.status(500).json({ error: 'Kryptografischer Serverfehler beim Erzeugen des JAR' });
  }
});

app.post('/api/presentation/callback', async (req, res) => {
  let { vp_token, state, wia_token, response } = req.body;

  console.log(`[RP Server] direct_post Callback erhalten.`);

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
    console.log('[RP Server] Kryptografischer JWE-Umschlag erkannt. Starte Entschlüsselung (direct_post.jwt)...');

    let assumedState = state || req.query.sid || req.query.state;

    if (assumedState && transactionStore.has(assumedState)) {
      const tx = transactionStore.get(assumedState);
      if (tx.privateKeyPem) {
        try {
          decryptedPayload = decryptJweResponse(tokenToDecrypt, tx.privateKeyPem);
          state = assumedState;
          console.log(`[RP Server] JWE erfolgreich entschlüsselt mit dem Schlüssel der Sitzung: ${state}`);
        } catch (err) {
          decryptionError = err;
          console.warn(`[RP Server] Direkter Entschlüsselungsvergleich fehlgeschlagen:`, err.message);
        }
      }
    }

    if (!decryptedPayload) {
      console.log('[RP Server] Durchsuche alle ausstehenden Transaktionen nach passendem Key...');
      for (const [txId, tx] of transactionStore.entries()) {
        if (tx.status === 'PENDING' && tx.privateKeyPem) {
          try {
            decryptedPayload = decryptJweResponse(tokenToDecrypt, tx.privateKeyPem);
            state = txId;
            console.log(`[RP Server] JWE erfolgreich entschlüsselt! Zuordnung zu Sitzung: ${state}`);
            break;
          } catch (err) {
          }
        }
      }
    }

    if (decryptedPayload) {
      vp_token = decryptedPayload.vp_token;
      wia_token = decryptedPayload.wia_token || wia_token;
    } else {
      console.error('[RP Server] ❌ JWE-Entschlüsselung fehlgeschlagen. Keine passende Session-ID gefunden.');
      return res.status(400).json({
        error: 'decryption_failed',
        error_description: decryptionError ? decryptionError.message : 'Die Payload konnte mit keinem aktiven Session-Verschlüsselungskey dekodiert werden.'
      });
    }
  }

  console.log(`[RP Server] Callback-Session (state): ${state}`);

  if (!state || !transactionStore.has(state)) {
    return res.status(400).json({ error: 'Transaktions-Kontext fehlt oder abgelaufen' });
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

    console.log(`[RP Server] Starte 4-Säulen-Validierung für Session: ${state}...`);
    const verificationResult = await verifier.verifyPresentation(parsedVpToken, wia_token);

    if (verificationResult.success) {
      console.log(`[RP Server] ✅ Verifizierung erfolgreich! ${verificationResult.format}-Format verarbeitet für ${state}.`);

      const responseCode = crypto.randomBytes(16).toString('hex');
      tx.status = 'SUCCESS';
      tx.claims = verificationResult.claims;
      tx.responseCode = responseCode;
      tx.isEncrypted = isEncrypted;
      tx.format = verificationResult.format; // Speicher Format (SD-JWT VC oder ISO mdoc)
      tx.integrityLog = verificationResult.integrityLog || [];
      tx.rawSdList = verificationResult.rawSdList || [];
      transactionStore.set(state, tx);

      res.status(200).json({
        redirect_uri: `${RP_CONFIG.publicUrl}/login-success.html?sid=${state}&code=${responseCode}`
      });
    } else {
      console.error(`[RP Server] ❌ Verifizierung fehlgeschlagen:`, verificationResult.errors);
      tx.status = 'FAILED';
      tx.errors = verificationResult.errors;
      transactionStore.set(state, tx);

      res.status(400).json({ error: 'Kryptografische 4-Säulen-Verifizierung fehlgeschlagen.' });
    }
  } catch (err) {
    console.error('Interner direct_post Fehler:', err);
    tx.status = 'FAILED';
    tx.errors.push(err.message);
    transactionStore.set(state, tx);
    res.status(500).json({ error: 'Interner Serverfehler im direct_post Callback' });
  }
});

app.get('/api/presentation/status', (req, res) => {
  const sessionId = req.query.sid;

  if (!sessionId || !transactionStore.has(sessionId)) {
    return res.status(404).json({ success: false, status: 'NOT_FOUND', error: 'Ungültige Sitzung' });
  }

  const tx = transactionStore.get(sessionId);

  if (tx.status === 'SUCCESS') {
    return res.json({
      success: true,
      status: 'SUCCESS',
      claims: tx.claims,
      responseCode: tx.responseCode,
      isEncrypted: tx.isEncrypted,
      format: tx.format, // Gibt das Format an das Frontend weiter
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
// TEIL 2: ENDPOINTS FÜR AUSSTELLUNG & BELEGVALIDIERUNG (OPENID4VCI)
// =============================================================================

app.get('/api/issuance/session-info', (req, res) => {
  const sessionId = req.query.sid;
  if (!sessionId || !transactionStore.has(sessionId)) {
    return res.status(404).json({ error: 'Sitzung nicht gefunden' });
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

  console.log(`[Issuer Server] Issuance Session initiiert. ID: ${sessionId}, Challenge: ${wiaChallenge}, Validity: ${customValidityDays} days`);

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
  console.log('[Issuer Server] Nonce Request erhalten.');
  const nonces = pidIssuer.generateNonceResponse();
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json(nonces);
});

app.post('/api/issuance/token', (req, res) => {
  console.log('[Issuer Server] Token Request erhalten.');

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
    console.log('[Issuer Server] ✅ Token-Request erfolgreich verifiziert. Generiere Access Token...');

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
    console.error('[Issuer Server] ❌ Token-Verifikation fehlgeschlagen:', tokenResult.errors);
    res.status(400).json({
      error: 'invalid_request',
      error_description: tokenResult.errors.join(', ')
    });
  }
});

app.post('/api/issuance/credential', (req, res) => {
  console.log('[Issuer Server] Credential Request erhalten.');

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('DPoP ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'DPoP Access Token im Authorization Header erforderlich.'
    });
  }
  const accessToken = authHeader.substring(5);
  const tokenData = accessTokenStore.get(accessToken);

  if (!tokenData) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Ungültiges, abgelaufenes oder unbekanntes Access Token.'
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
      console.log('[Issuer Server] ✅ Belegbesitz-Verifikation erfolgreich. Erzeuge ISO mdoc (mDL)...');

      const claims = tokenData.claims || {
        given_name: 'Erika',
        family_name: 'Mustermann',
        birth_date: '1998-08-12',
        driving_privileges: 'B',
        issuing_country: 'DE'
      };

      const validityDays = tokenData.validityDays || 3650; // Default 10 years for mDL

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
        console.log(`[Issuer Server] ✅ Session ${tokenData.sid} Status auf SUCCESS gesetzt.`);
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
      console.log('[Issuer Server] ✅ Belegbesitz-Verifikation erfolgreich. Erzeuge SD-JWT VC...');

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
        console.log(`[Issuer Server] ✅ Session ${tokenData.sid} Status auf SUCCESS gesetzt.`);
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
    console.error('[Issuer Server] ❌ Belegbesitz-Verifikation fehlgeschlagen:', credResult.errors);
    res.status(400).json({
      error: 'invalid_proof',
      error_description: credResult.errors.join(', ')
    });
  }
});

// Starten des API-Servers
app.listen(PORT, () => {
  console.log(`\n=== EUDI WALLET INTEGRATED SERVER v18 (PRESENTATION & ISSUANCE) ===`);
  console.log(`Server läuft lokal auf: http://localhost:${PORT}`);
  console.log(`Öffentliche RP-Identität (client_id): ${RP_CONFIG.clientId}`);
  console.log(`Öffentliche Issuer-Identität (issuer_id): ${ISSUER_CONFIG.issuerId}`);
  console.log(`Warte auf Wallet-Verbindungen (Präsentation und Ausstellung)...\n`);
});

module.exports = app;