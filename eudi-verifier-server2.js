/**
 * EUDI Wallet REST API Server
 * 
 * This mdule is mimpülementing SPI endpoints for:
 * 1. RP backend for facilitating credential presentation requests (OpenID4VP) with JWE encryption (direct_post.jwt)
 * 2. Issuer backend for credential issuance of a mock PID (OpenID4VCI & HAIP 1.0)
 * 
 * It will generate demo keys on demand and stores them in ./demo-keys.json
 */

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dotenv = require("dotenv");
const { EUDIVerifier } = require('./eudi-verifier-helper.js');
const { EUDIPIDIssuerVerifier } = require('./eudi-issuer-verifier.js');
const { Logger } = require("./util/logger.js");

const app = express();
const PORT = process.env.PORT || 3000;

// read .env
dotenv.config();

// Middleware konfigurieren
app.use(cors({ origin: true, credentials: true }));
app.use((req, res, next) => {
  res.setHeader('ngrok-skip-browser-warning', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  next();
});
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

// =============================================================================
// DEBUG LOGGING
// =============================================================================

let debugLogging = false;
let logLevel = 0;

if (process.argv && process.argv.length > 2) {
  let args = process.argv.slice(2);
  if (args.find((item) => item.trim() == "-d")) {
    debugLogging = true;
  }
  if (args.find((item) => item.trim() == "--debug")) {
    debugLogging = true;
  }
  if (args.find((item) => item.trim().startsWith("--log-level="))) {
    let level = parseInt(
      args.find((item) => item.trim().startsWith("--log-level=")).trim().split("=")[1],
    );
    console.log("⚠️ log level: ", level);
    logLevel = level;
    if (level > 0) {
      debugLogging = true;
    }
  }
}

console.log("ℹ️ DEBUG LOGGING: ", debugLogging);
console.log("ℹ️ instantiating logger");
const logger = new Logger(debugLogging, logLevel);

// =============================================================================
// SZENARIEN- & ZERTIFIKATS-VERWALTUNG (scenarios.json & CLI-PARAMETER)
// =============================================================================

let allScenariosMap = {};
let activeScenario = null;
let activeScenarioId = '';
let activeDcqlQuery = null;

let accessCertDerBuffer;
let accessCertPrivateKeyPem;
let registrationCertDerBuffer;
let clientIdX509Hash = '';
let x5cHeaderArray = [];
let verifierInfoArray = [];

function getRequestedScenarioId() {
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--scenario=')) {
      return arg.split('=')[1].trim();
    }
    if ((arg === '--scenario' || arg === '-s') && args[i + 1]) {
      return args[i + 1].trim();
    }
    if (!arg.startsWith('-')) {
      return arg.trim();
    }
  }
  return process.env.SCENARIO || null;
}

function loadScenarioAndCertificates() {
  console.log('[Scenario Manager v29] Lade Szenarien aus scenarios.json...');
  const scenariosPath = path.join(__dirname, 'scenarios.json');
  let scenariosData = null;

  if (fs.existsSync(scenariosPath)) {
    try {
      scenariosData = JSON.parse(fs.readFileSync(scenariosPath, 'utf8'));
      console.log('[Scenario Manager v29] scenarios.json erfolgreich eingelesen.');
    } catch (err) {
      console.error('[Scenario Manager v29] Fehler beim Lesen von scenarios.json:', err.message);
    }
  } else {
    console.warn('[Scenario Manager v29] scenarios.json nicht gefunden. Verwende integrierte Fallback-Szenarien.');
  }

  const scenarios = scenariosData?.scenarios || {
    "pid_age_18": {
      "name": "DE National PID - Altersnachweis (18+)",
      "description": "Fordert Vorname, Nachname und die Bestätigung 'age_equal_or_over 18' aus der deutschen PID an.",
      "certs": {
        "accessCertificate": "certs/access_certificate.pem",
        "accessPrivateKey": "certs/access_certificate_key.pem",
        "registrationCertificate": "certs/registration_certificate.jwt"
      },
      "dcqlQuery": {
        "credentials": [
          {
            "id": "pid_age_credential",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
            "claims": [
              { "path": ["given_name"] },
              { "path": ["family_name"] },
              { "path": ["age_equal_or_over", "18"] }
            ]
          }
        ]
      }
    }
  };

  const requestedId = getRequestedScenarioId();
  const defaultId = scenariosData?.defaultScenario || Object.keys(scenarios)[0];

  if (requestedId && scenarios[requestedId]) {
    activeScenarioId = requestedId;
    console.log(`[Scenario Manager v29] Ausgewähltes Szenario via CLI/ENV: "${activeScenarioId}"`);
  } else {
    if (requestedId) {
      console.warn(`[Scenario Manager v29] WARNUNG: Szenario-ID "${requestedId}" nicht in scenarios.json gefunden! Nutze Default.`);
    }
    activeScenarioId = defaultId;
    console.log(`[Scenario Manager v29] Ausgewähltes Default-Szenario: "${activeScenarioId}"`);
  }

  allScenariosMap = scenarios;
  activeScenario = scenarios[activeScenarioId];
  activeDcqlQuery = activeScenario.dcqlQuery;

  console.log(`\n================================================================`);
  console.log(`  AKTIVES SZENARIO: [ ${activeScenarioId} ]`);
  console.log(`  Name        : ${activeScenario.name || 'Unbenannt'}`);
  console.log(`  Description : ${activeScenario.description || 'Keine'}`);
  console.log(`================================================================\n`);

  console.log('[Scenario Manager v29] Verfügbare Szenarien in scenarios.json:');
  Object.keys(scenarios).forEach(id => {
    const mark = id === activeScenarioId ? ' -> [AKTIV]' : '          ';
    console.log(`  ${mark} ${id.padEnd(22)} : ${scenarios[id].name || ''}`);
  });
  console.log('');

  loadCertificatesForScenario(activeScenario.certs);
}

function loadCertificatesForScenario(certsConfig = {}) {
  const certsDir = path.join(__dirname, 'certs');

  const accessCertPath = certsConfig.accessCertificate
    ? path.resolve(__dirname, certsConfig.accessCertificate)
    : path.join(certsDir, 'access_certificate.pem');

  const accessKeyPath = certsConfig.accessPrivateKey
    ? path.resolve(__dirname, certsConfig.accessPrivateKey)
    : path.join(certsDir, 'access_certificate_key.pem');

  const regCertPath = certsConfig.registrationCertificate
    ? path.resolve(__dirname, certsConfig.registrationCertificate)
    : path.join(certsDir, 'registration_certificate.jwt');

  let loadedAccess = false;

  try {
    if (fs.existsSync(accessKeyPath)) {
      accessCertPrivateKeyPem = fs.readFileSync(accessKeyPath, 'utf8');
      console.log('[Cert Loader v29] Private Key geladen aus:', path.basename(accessKeyPath));
    }

    if (fs.existsSync(accessCertPath) && accessCertPrivateKeyPem) {
      const rawContent = fs.readFileSync(accessCertPath);
      const x509 = new crypto.X509Certificate(rawContent);
      accessCertDerBuffer = x509.raw;
      loadedAccess = true;
      console.log('[Cert Loader v29] Access Certificate geladen aus:', path.basename(accessCertPath));
    }
  } catch (e) {
    console.warn('[Cert Loader v29] Warnung beim Laden des Access Certificates:', e.message);
  }

  let registrationJwtString = null;
  try {
    if (fs.existsSync(regCertPath)) {
      const content = fs.readFileSync(regCertPath, 'utf8').trim();
      if (content.startsWith('eyJ')) {
        registrationJwtString = content;
        console.log('[Cert Loader v29] Registration Certificate (JWT) geladen aus:', path.basename(regCertPath));
      } else {
        registrationCertDerBuffer = fs.readFileSync(regCertPath);
        console.log('[Cert Loader v29] Registration Certificate (DER) geladen aus:', path.basename(regCertPath));
      }
    }
  } catch (e) {
    console.warn('[Cert Loader v29] Warnung beim Laden des Registration Certificates:', e.message);
  }

  if (!loadedAccess) {
    console.log('[Cert Loader v29] Synthetisiere Access Certificate & Key (Demo/Fallback)...');
    const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    accessCertPrivateKeyPem = keyPair.privateKey.export({ type: 'sec1', format: 'pem' });
    accessCertDerBuffer = Buffer.concat([Buffer.from([0x30, 0x82, 0x01, 0x20]), crypto.randomBytes(284)]);
  }

  const sha256Hash = crypto.createHash('sha256').update(accessCertDerBuffer).digest();
  clientIdX509Hash = 'x509_hash:' + sha256Hash.toString('base64url');
  console.log('[Cert Loader v29] HAIP client_id:', clientIdX509Hash);

  x5cHeaderArray = [accessCertDerBuffer.toString('base64')];

  if (registrationJwtString) {
    verifierInfoArray = [
      {
        format: 'http://etsi.org/119475/v1.1.1',
        data: registrationJwtString
      }
    ];
  } else {
    if (!registrationCertDerBuffer) {
      registrationCertDerBuffer = Buffer.concat([Buffer.from([0x30, 0x82, 0x01, 0x20]), crypto.randomBytes(284)]);
    }
    verifierInfoArray = [
      {
        format: 'http://etsi.org/119475/v1.1.1',
        data: registrationCertDerBuffer.toString('base64')
      }
    ];
  }
}


function switchScenario(scenarioId) {
  if (!scenarioId || !allScenariosMap[scenarioId]) {
    console.warn(`[Scenario Manager v27] Szenario-ID "${scenarioId}" nicht gefunden.`);
    return false;
  }
  activeScenarioId = scenarioId;
  activeScenario = allScenariosMap[scenarioId];
  activeDcqlQuery = activeScenario.dcqlQuery;
  loadCertificatesForScenario(activeScenario.certs);
  if (typeof RP_CONFIG !== 'undefined') {
    RP_CONFIG.clientId = clientIdX509Hash || 'x509_hash:demo';
  }
  console.log(`[Scenario Manager v27] Dynamischer Wechsel zu Szenario: "${activeScenarioId}" (${activeScenario.name || ''})`);
  return true;
}

loadScenarioAndCertificates();

// Konfiguration der Relying Party (Präsentation)
const RP_CONFIG = {
  clientId: clientIdX509Hash || 'x509_hash:demo',
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


function deriveConcatKDF(sharedSecret, keyLengthBytes, encAlg, apuB64, apvB64) {
  const algorithmId = Buffer.from(encAlg, 'ascii');
  const algIdLength = Buffer.alloc(4);
  algIdLength.writeUInt32BE(algorithmId.length, 0);

  let apuBuf = Buffer.alloc(0);
  if (apuB64) apuBuf = Buffer.from(apuB64, 'base64url');
  const apuLength = Buffer.alloc(4);
  apuLength.writeUInt32BE(apuBuf.length, 0);

  let apvBuf = Buffer.alloc(0);
  if (apvB64) apvBuf = Buffer.from(apvB64, 'base64url');
  const apvLength = Buffer.alloc(4);
  apvLength.writeUInt32BE(apvBuf.length, 0);

  const suppPubInfo = Buffer.alloc(4);
  suppPubInfo.writeUInt32BE(keyLengthBytes * 8, 0);

  const round1Counter = Buffer.from([0x00, 0x00, 0x00, 0x01]);

  const kdfInput = Buffer.concat([
    round1Counter,
    sharedSecret,
    algIdLength,
    algorithmId,
    apuLength,
    apuBuf,
    apvLength,
    apvBuf,
    suppPubInfo
  ]);

  const hash = crypto.createHash('sha256').update(kdfInput).digest();
  return hash.subarray(0, keyLengthBytes);
}


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

app.get('/api/scenarios', (req, res) => {
  res.json({
    success: true,
    activeScenarioId: activeScenarioId,
    scenarios: allScenariosMap,
    clientId: RP_CONFIG.clientId,
    publicUrl: RP_CONFIG.publicUrl
  });
});

app.get('/api/scenario', (req, res) => {
  res.json({
    success: true,
    scenarioId: activeScenarioId,
    scenario: activeScenario,
    scenarios: allScenariosMap,
    clientId: RP_CONFIG.clientId,
    publicUrl: RP_CONFIG.publicUrl
  });
});

app.post('/api/scenario/select', (req, res) => {
  const { scenarioId } = req.body || {};
  if (switchScenario(scenarioId)) {
    res.json({
      success: true,
      scenarioId: activeScenarioId,
      scenario: activeScenario,
      clientId: RP_CONFIG.clientId
    });
  } else {
    res.status(400).json({ success: false, error: `Unbekanntes Szenario: ${scenarioId}` });
  }
});

app.all('/api/presentation/initiate', (req, res) => {
  const reqScenario = req.query.scenario || (req.body && req.body.scenario);
  if (reqScenario && allScenariosMap[reqScenario]) {
    switchScenario(reqScenario);
  }
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

  const dcqlQuery = activeDcqlQuery;

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
      vp_formats_supported: {
        "dc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "Ed25519"],
          "kb-jwt_alg_values": ["ES256", "Ed25519"]
        },
        "mso_mdoc": {
          "alg": ["ES256", "Ed25519"]
        }
      },
      encrypted_response_enc_values_supported: ["A128GCM", "A256GCM"]
    },
    verifier_info: verifierInfoArray
  };

  const jwtHeader = {
    alg: 'ES256',
    typ: 'oauth-authz-req+jwt'
  };
  if (x5cHeaderArray.length > 0) {
    jwtHeader.x5c = x5cHeaderArray;
  } else if (rpSigningCertBase64) {
    jwtHeader.x5c = [rpSigningCertBase64];
  }

  try {
    const tokenInput = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(requestPayload)).toString('base64url')}`;

    // Nutze den zum x5c-Zertifikat passenden privaten Schlüssel (accessCertPrivateKeyPem)
    const signingKey = accessCertPrivateKeyPem || rpSigningKeys.privateKey;

    // ES256 / JWS erfordert IEEE P1363 Enkodierung (64-Byte r||s Buffer)
    const signature = crypto.sign('SHA256', Buffer.from(tokenInput), {
      key: signingKey,
      dsaEncoding: 'ieee-p1363'
    });
    const signedJwt = `${tokenInput}.${signature.toString('base64url')}`;

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
  let { vp_token, state, wia_token, response, error, error_description } = req.body || {};

  console.log(`[RP Server] direct_post Callback erhalten.`);

  if (error) {
    console.error(`[RP Server] ❌ Wallet-Fehler erhalten: ${error} (${error_description || ''})`);
    const sessionState = state || req.query.sid;
    if (sessionState && transactionStore.has(sessionState)) {
      const tx = transactionStore.get(sessionState);
      tx.status = 'FAILED';
      tx.errors = [`Wallet-Protokollfehler (${error}): ${error_description || 'Anfrage von Wallet abgelehnt'}`];
      transactionStore.set(sessionState, tx);
    }
    return res.status(200).json({ status: 'ACK' });
  }

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
      if (decryptedPayload.error) {
        console.error(`[RP Server] ❌ Wallet hat im JWE einen Fehler übermittelt: ${decryptedPayload.error} (${decryptedPayload.error_description || ''})`);
        if (state && transactionStore.has(state)) {
          const tx = transactionStore.get(state);
          tx.status = 'FAILED';
          tx.errors = [`Wallet-Protokollfehler (${decryptedPayload.error}): ${decryptedPayload.error_description || 'Anfrage abgelehnt'}`];
          transactionStore.set(state, tx);
        }
        return res.status(200).json({ status: 'ACK' });
      }
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
      publicUrl: RP_CONFIG.publicUrl,
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

      res.status(400).json({
        error: 'Kryptografische 4-Säulen-Verifizierung fehlgeschlagen.',
        details: verificationResult.errors
      });
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
    credential_configuration_ids: format === 'mso_mdoc' ? ['mDL_mso_mdoc'] : (format === 'employee_sd_jwt' || format === 'Employee_ID_SD_JWT_VC' ? ['Employee_ID_SD_JWT_VC'] : ['PID_SD_JWT_VC']),
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


// Route zur Bereitstellung von Firmenlogos und Visuals für Credential Display Metadata
app.get('/assets/company_logo.png', (req, res) => {
  const candidatePaths = [
    path.join(__dirname, 'company_logo.png'),
    path.join(__dirname, 'assets', 'company_logo.png')
  ];
  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      return res.sendFile(p);
    }
  }
  res.status(404).send('Logo image not found');
});

app.get([
  '/.well-known/openid-credential-issuer',
  '/.well-known/openid-credential-issuer/api/issuance',
  '/api/issuance/.well-known/openid-credential-issuer'
], (req, res) => {
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
      "Employee_ID_SD_JWT_VC": {
        format: "dc+sd-jwt",
        scope: "Employee_ID_SD_JWT_VC",
        credential_signing_alg_values_supported: ["ES256"],
        cryptographic_binding_methods_supported: ["jwk"],
        proof_types_supported: {
          "jwt": {
            "proof_signing_alg_values_supported": ["ES256"]
          }
        },
        vct: "urn:company:employee_id:1",
        credential_metadata: {
          display: [
            {
              name: "Muster GmbH - Digitaler Mitarbeiter-Ausweis",
              locale: "de-DE",
              description: "Offizieller fälschungssicherer Betriebsausweis & Digital Access Badge der Muster GmbH",
              background_color: "#0f172a",
              text_color: "#ffffff",
              logo: {
                uri: `${ISSUER_CONFIG.publicUrl}/assets/company_logo.png`,
                alt_text: "Muster GmbH Secure Access Logo"
              }
            }
          ],
          claims: [
            {
              path: ["given_name"],
              display: [{ name: "Vorname", locale: "de-DE" }]
            },
            {
              path: ["family_name"],
              display: [{ name: "Nachname", locale: "de-DE" }]
            },
            {
              path: ["employee_id"],
              display: [{ name: "Personalnummer / ID", locale: "de-DE" }]
            },
            {
              path: ["department"],
              display: [{ name: "Abteilung", locale: "de-DE" }]
            },
            {
              path: ["role"],
              display: [{ name: "Berechtigungsrolle", locale: "de-DE" }]
            }
          ]
        }
      },
      "mDL_mso_mdoc": {
        format: "mso_mdoc",
        scope: "mDL_mso_mdoc",
        doctype: "org.iso.18013.5.1.mDL",
        credential_signing_alg_values_supported: ["ES256"],
        cryptographic_binding_methods_supported: ["jwk"],
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

  try {
    const issuerPublicKeyJwk = demoIssuerKeys.publicKey.export({ format: 'jwk' });
    const certsForHeader = (typeof x5cHeaderArray !== 'undefined' && x5cHeaderArray.length > 0)
      ? x5cHeaderArray
      : [rpSigningCertBase64];

    const signingKey = accessCertPrivateKeyPem || demoIssuerKeys.privateKey;

    const jwtHeader = {
      alg: 'ES256',
      typ: 'openidvci-issuer-metadata+jwt'
    };

    if (accessCertPrivateKeyPem && certsForHeader && certsForHeader.length > 0) {
      jwtHeader.x5c = certsForHeader;
    } else {
      jwtHeader.jwk = demoIssuerKeys.publicKey.export({ format: 'jwk' });
    }

    const basePayload = {
      ...metadata,
      iss: issuerUrl,
      sub: issuerUrl,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 86400
    };

    const tokenInput1 = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(basePayload)).toString('base64url')}`;
    const signature1 = crypto.sign('SHA256', Buffer.from(tokenInput1), {
      key: signingKey,
      dsaEncoding: 'ieee-p1363'
    });
    const initialJwt = `${tokenInput1}.${signature1.toString('base64url')}`;

    const jwtPayloadFinal = {
      ...basePayload,
      signed_metadata: initialJwt
    };

    const tokenInput2 = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(jwtPayloadFinal)).toString('base64url')}`;
    const signature2 = crypto.sign('SHA256', Buffer.from(tokenInput2), {
      key: signingKey,
      dsaEncoding: 'ieee-p1363'
    });
    const finalSignedMetadataJwt = `${tokenInput2}.${signature2.toString('base64url')}`;

    console.log('[Issuer Server v37] signed_metadata (HAIP-konform) erzeugt.');

    const acceptHeader = req.headers['accept'] || '';
    if (acceptHeader.includes('application/jwt')) {
      res.setHeader('Content-Type', 'application/jwt');
      res.setHeader('Cache-Control', 'no-store');
      return res.send(finalSignedMetadataJwt);
    }

    res.json({
      ...metadata,
      signed_metadata: finalSignedMetadataJwt
    });
  } catch (e) {
    console.error('[Issuer Server] Fehler beim Signieren von signed_metadata:', e);
    res.json(metadata);
  }
});


app.get([
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
  '/.well-known/oauth-authorization-server/api/issuance',
  './well-known/openid-configuration/api/issuance',
  '/api/issuance/.well-known/openid-configuration',
  '/api/issuance/.well-known/oauth-authorization-server'
], (req, res) => {
  const issuerUrl = `${ISSUER_CONFIG.publicUrl}/api/issuance`;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    issuer: issuerUrl,
    authorization_endpoint: `${issuerUrl}/authorize`,
    token_endpoint: `${issuerUrl}/token`,
    nonce_endpoint: `${issuerUrl}/nonce`,
    credential_endpoint: `${issuerUrl}/credential`,
    grant_types_supported: ["authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"],
    response_types_supported: ["code"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "attest_jwt_client_auth"],
    dpop_signing_alg_values_supported: ["ES256", "RS256"]
  });
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
      scope: storedFormat === 'mso_mdoc' ? 'mDL_mso_mdoc' : (storedFormat === 'employee_sd_jwt' || storedFormat === 'Employee_ID_SD_JWT_VC' ? 'Employee_ID_SD_JWT_VC' : 'PID_SD_JWT_VC'),
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

      const isEmployee = format === 'employee_sd_jwt' || tokenData.scope === 'Employee_ID_SD_JWT_VC';

      const defaultClaims = isEmployee ? {
        given_name: 'Max',
        family_name: 'Mustermann',
        employee_id: 'EMP-2026-8942',
        department: 'IT-Infrastruktur & Sicherheit',
        role: 'Senior Security Architect',
        vct: 'urn:company:employee_id:1'
      } : {
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
      if (isEmployee && !finalClaims.vct) {
        finalClaims.vct = 'urn:company:employee_id:1';
      }
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
  console.log(`\n=== EUDI WALLET INTEGRATED SERVER v34 (PRESENTATION & ISSUANCE) ===`);
  console.log(`Server läuft lokal auf: http://localhost:${PORT}`);
  console.log(`Öffentliche RP-Identität (client_id): ${RP_CONFIG.clientId}`);
  console.log(`Öffentliche Issuer-Identität (issuer_id): ${ISSUER_CONFIG.issuerId}`);
  console.log(`Warte auf Wallet-Verbindungen (Präsentation und Ausstellung)...\n`);
});

module.exports = app;