/**
 * EUDI Wallet REST API Server
 * 
 * This mdule is implementing API endpoints for:
 * 1. RP backend for facilitating credential presentation requests (OpenID4VP) with JWE encryption (direct_post.jwt)
 * 2. Issuer backend for credential issuance of a mock PID (OpenID4VCI & HAIP 1.0)
 * 
 * It will generate demo keys on demand as fallback and will store them in ./demo-keys.json
 */

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const { EUDIVerifier } = require('./eudi-verifier-helper');
const { EUDIPIDIssuerVerifier } = require('./eudi-issuer-verifier');
const { Logger, log_middleware } = require("./util/logger.js");

// set up app instance
const app = express();
const PORT = process.env.PORT || 3000;

// read .env
dotenv.config();

// check whether strict RFC9101 mode is enabled
function isRfc9101StrictModeEnabled() {
  return process.env.ENFORCE_RFC9101_STRICT === 'true' ||
    process.env.ENFORCE_JAR_ONE_TIME_USE === 'true' ||
    process.env.ENFORCE_JAR_EXPIRATION === 'true';
}

// configure middleware
app.use(cors({ origin: true, credentials: true }));
app.use((req, res, next) => {
  res.setHeader('ngrok-skip-browser-warning', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  next();
});
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// logging middleware
app.use(log_middleware);

// serve static files from current directory
app.use(express.static(__dirname));

// route for serving main frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// route for serving the error page
app.get(['/error.html', '/error'], (req, res) => {
  const txtFile = path.join(__dirname, 'error.html.txt');
  const htmlFile = path.join(__dirname, 'error.html');
  if (fs.existsSync(txtFile)) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.sendFile(txtFile);
  }
  if (fs.existsSync(htmlFile)) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.sendFile(htmlFile);
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// session management for storing nonces + verification results
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 300000 } // validity period = 5min
}));

// in-memory store for transient status sync (Redis "lite")
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
// SCENARIO & CERTIFICATE MANAGEMENT (scenarios.json & CLI PARAMS)
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
  console.log('[SCEN] loading scenarios from file: scenarios.json...');
  const scenariosPath = path.join(__dirname, 'scenarios.json');
  let scenariosData = null;

  if (fs.existsSync(scenariosPath)) {
    try {
      scenariosData = JSON.parse(fs.readFileSync(scenariosPath, 'utf8'));
      console.log('[SCEN] scenarios.json has been loaded sucessfully');
    } catch (err) {
      console.error('[SCEN] error while loading scenarios.json:', err.message);
    }
  } else {
    console.warn('[SCEN] scenarios.json not found; falling back to hard-coded default scenarios');
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
        ],
        "credential_sets": {
          "options": [
            ["pid_age_credential"]
          ]
        }
      }
    }
  };

  const requestedId = getRequestedScenarioId();
  const defaultId = scenariosData?.defaultScenario || Object.keys(scenarios)[0];

  if (requestedId && scenarios[requestedId]) {
    activeScenarioId = requestedId;
    console.log(`[SCEN] selected scenario via CLI/ENV: "${activeScenarioId}"`);
  } else {
    if (requestedId) {
      console.warn(`[SCEN] scenario ID "${requestedId}" not found in scenarios.json gefunden; falling back to default`);
    }
    activeScenarioId = defaultId;
    console.log(`[SCEN] selected default scneario: "${activeScenarioId}"`);
  }

  allScenariosMap = scenarios;
  activeScenario = scenarios[activeScenarioId];
  activeDcqlQuery = activeScenario.dcqlQuery;

  console.log(`================================================================`);
  console.log(`  ACTIVE SCENARIO: [ ${activeScenarioId} ]`);
  console.log(`  Name           : ${activeScenario.name || 'Unknown'}`);
  console.log(`  Description    : ${activeScenario.description || 'None'}`);
  console.log(`================================================================`);

  console.log('[SCEN] available scenarios in scenarios.json:');
  Object.keys(scenarios).forEach(id => {
    const mark = id === activeScenarioId ? ' -> [ACTIVE]' : '           ';
    console.log(`  ${mark} ${id.padEnd(22)} : ${scenarios[id].name || ''}`);
  });
  console.log('');

  console.log("[SCEN] loading certificates for selected scenario...");
  loadCertificatesForScenario(activeScenario.certs);
}

function loadCertificatesForScenario(certsConfig = {}) {
  const certsDir = path.join(__dirname, 'certs');

  const accessCertPath = certsConfig.accessCertificate
    ? path.resolve(__dirname, certsConfig.accessCertificate)
    : path.join(certsDir, 'access_certificate.cer');

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
      console.log('[CERT] private key loaded from file:', path.basename(accessKeyPath));
    }
    else {
      console.log("[CERT] unable to load private key from file:", path.basename(accessKeyPath));
    }

    if (fs.existsSync(accessCertPath) && accessCertPrivateKeyPem) {
      const rawContent = fs.readFileSync(accessCertPath);
      const x509 = new crypto.X509Certificate(rawContent);
      accessCertDerBuffer = x509.raw;
      loadedAccess = true;
      console.log('[CERT] access certificate loaded from file:', path.basename(accessCertPath));
    }
    else {
      console.log(`[CERT] unable to load access certificate from: ${accessCertPath}`);
    }
  } catch (e) {
    console.warn('[CERT] error while loading the access certificate:', e.message);
  }

  let registrationJwtString = null;
  try {
    if (fs.existsSync(regCertPath)) {
      const content = fs.readFileSync(regCertPath, 'utf8').trim();
      if (content.startsWith('eyJ')) {
        registrationJwtString = content;
        console.log('[CERT] registration certificate (JWT) loaded from file:', path.basename(regCertPath));
      } else {
        registrationCertDerBuffer = fs.readFileSync(regCertPath);
        console.log('[CERT] registration certificate (DER) loaded from file:', path.basename(regCertPath));
      }
    }
  } catch (e) {
    console.warn('[CERT] error while loading the registration certificate:', e.message);
  }

  if (!loadedAccess) {
    console.log('[CERT] synthesizing access cert & key (fallback)...');
    const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    accessCertPrivateKeyPem = keyPair.privateKey.export({ type: 'sec1', format: 'pem' });
    accessCertDerBuffer = Buffer.concat([Buffer.from([0x30, 0x82, 0x01, 0x20]), crypto.randomBytes(284)]);
  }

  const sha256Hash = crypto.createHash('sha256').update(accessCertDerBuffer).digest();
  clientIdX509Hash = 'x509_hash:' + sha256Hash.toString('base64url');
  console.log('[CERT] HAIP / x509 client_id:', clientIdX509Hash);

  x5cHeaderArray = [accessCertDerBuffer.toString('base64')];

  if (registrationJwtString) {
    verifierInfoArray = [
      {
        format: 'registration_cert',
        data: registrationJwtString
      }
    ];
  } else {
    if (!registrationCertDerBuffer) {
      registrationCertDerBuffer = Buffer.concat([Buffer.from([0x30, 0x82, 0x01, 0x20]), crypto.randomBytes(284)]);
    }
    verifierInfoArray = [
      {
        format: 'registration_cert',
        data: registrationCertDerBuffer.toString('base64')
      }
    ];
  }
}

function switchScenario(scenarioId) {
  if (!scenarioId || !allScenariosMap[scenarioId]) {
    console.warn(`[SCEN] scenario ID "${scenarioId}" was not found`);
    return false;
  }
  activeScenarioId = scenarioId;
  activeScenario = allScenariosMap[scenarioId];
  activeDcqlQuery = activeScenario.dcqlQuery;
  loadCertificatesForScenario(activeScenario.certs);
  if (typeof RP_CONFIG !== 'undefined') {
    RP_CONFIG.clientId = clientIdX509Hash || 'x509_hash:demo';
  }
  console.log(`[SCEN] dynamic switch to scenario: "${activeScenarioId}" (${activeScenario.name || ''})`);
  return true;
}

loadScenarioAndCertificates();

// RP configuration
const RP_CONFIG = {
  clientId: clientIdX509Hash || 'x509_hash:demo',
  publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
  trustedIssuerKeys: [],
  trustedWalletKeys: []
};

// issuer configuration
const ISSUER_CONFIG = {
  issuerId: process.env.ISSUER_ID || `http://localhost:${PORT}/api/issuance`, // dynamic IssuerId mathcing the server host
  publicUrl: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
  trustedWalletKeys: []
};

// generate crypto keys for demo purposes (simulated trust store / PKI)
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
  console.log('[SERV] RP signing certificate loaded + extracted x5c');
} catch (err) {
  console.error('Error whie loading RP cert/key:', err);
  rpSigningKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

try {
  demoIssuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  demoWalletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  // populate trust store
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
  console.log('[SERV] demo keys have been successfully exported to ./demo-keys.json');
} catch (e) {
  console.error('Error while generating the keys:', e);
}

// instantiating the issuer verifier
const pidIssuer = new EUDIPIDIssuerVerifier({
  issuerId: ISSUER_CONFIG.issuerId,
  issuerPrivateKeyPem: demoIssuerKeys.privateKey.export({ type: 'sec1', format: 'pem' }),
  issuerPublicKeyPem: demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }),
  trustedWalletKeys: ISSUER_CONFIG.trustedWalletKeys
});

// =============================================================================
// CRYPTO AUX FUNCTIONS FOR JWE DECRYPTION (ECDH-ES + A128GCM/A256GCM)
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
      throw new Error("Floating point numbers not supported on this crypto layer");
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
    throw new Error('Invalid JWE format; 5 segments were expected');
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
    throw new Error('Ephemeral public key (epk) missing in JWE header');
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
// SPREAD ENDPOINTS FOR PRESENTATION (OPENID4VP)
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
    res.status(400).json({ success: false, error: `Unknown scenario: ${scenarioId}` });
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
    console.error('Error during key pair generation for JWE:', e);
  }

  req.session.sessionId = sessionId;
  req.session.expectedNonce = nonce;
  req.session.verificationStatus = 'PENDING';

  const nowSec = Math.floor(Date.now() / 1000);
  const ttlSeconds = parseInt(process.env.JAR_LIFETIME_SECONDS || '300', 10);

  transactionStore.set(sessionId, {
    type: 'PRESENTATION',
    nonce: nonce,
    status: 'PENDING',
    claims: null,
    errors: [],
    responseCode: null,
    privateKeyPem: privateKeyPem,
    publicKeyJwk: publicKeyJwk,
    createdAt: nowSec,
    expiresAt: nowSec + ttlSeconds,
    requestJwtFetched: false
  });

  const requestUri = `${RP_CONFIG.publicUrl}/api/presentation/request-jwt?sid=${sessionId}`;
  const qrCodeUrl = `openid4vp://?client_id=${encodeURIComponent(RP_CONFIG.clientId)}&request_uri=${encodeURIComponent(requestUri)}`;

  console.log(`[RP] session initiated; ID: ${sessionId}, expected nonce: ${nonce}`);

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
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid or expired transaction ID' });
  }

  const tx = transactionStore.get(sessionId);
  const nowSec = Math.floor(Date.now() / 1000);

  // RFC 9101 strict mode guard rails
  if (isRfc9101StrictModeEnabled()) {
    // 1. Expiration Check
    if (tx.expiresAt && nowSec > tx.expiresAt) {
      console.error(`[RP] ❌ JAR request object for session ${sessionId} is expired (exp: ${tx.expiresAt}, current: ${nowSec}).`);
      return res.status(410).json({
        error: 'invalid_request',
        error_description: 'Request object (JAR) has expired'
      });
    }

    // 2. One-Time Retrieval Check
    if (tx.requestJwtFetched) {
      console.error(`[RP] ❌ JAR request object for session ${sessionId} already consumed`);
      return res.status(410).json({
        error: 'invalid_request',
        error_description: 'Request object (JAR) has been consumed already'
      });
    }

    // mark as consumed
    tx.requestJwtFetched = true;
    transactionStore.set(sessionId, tx);
  }

  const dcqlQuery = activeDcqlQuery;
  const iat = tx.createdAt || nowSec;
  const exp = tx.expiresAt || (nowSec + 300);

  const requestPayload = {
    iss: RP_CONFIG.clientId,
    aud: "https://self-issued.me/v2",
    iat: iat,
    exp: exp,
    // scope: "openid", // <-- will break presentation request if present
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

    // use the private key mathcing with the x5c cert (accessCertPrivateKeyPem)
    const signingKey = accessCertPrivateKeyPem || rpSigningKeys.privateKey;

    // ES256 / JWS requires IEEE P1363 encoding (64 byte r||s buffer)
    const signature = crypto.sign('SHA256', Buffer.from(tokenInput), {
      key: signingKey,
      dsaEncoding: 'ieee-p1363'
    });
    const signedJwt = `${tokenInput}.${signature.toString('base64url')}`;

    console.log(`[RP] JAR request for session ${sessionId} has been delivered to wallet`);

    res.setHeader('Content-Type', 'application/oauth-authz-req+jwt');
    //res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.send(signedJwt);
  } catch (err) {
    console.error('JAR signing error:', err);
    res.status(500).json({ error: 'Cryptographic server error while generating the JAR' });
  }
});

app.post('/api/presentation/callback', async (req, res) => {
  let { vp_token, state, wia_token, response, error, error_description } = req.body || {};

  console.log(`[RP] direct_post callback received`);

  if (error) {
    console.error(`[RP] ❌ received error from wallet: ${error} (${error_description || ''})`);
    const sessionState = state || req.query.sid;
    if (sessionState && transactionStore.has(sessionState)) {
      const tx = transactionStore.get(sessionState);
      tx.status = 'FAILED';
      tx.errors = [`Wallet protocol error (${error}): ${error_description || 'Request rejected by wallet'}`];
      transactionStore.set(sessionState, tx);
    }
    const errRedirectUrl = `${RP_CONFIG.publicUrl}/error.html?sid=${encodeURIComponent(sessionState || '')}&error=${encodeURIComponent(error)}&error_description=${encodeURIComponent(error_description || 'Request rejected by wallet')}`;
    return res.status(200).json({ redirect_uri: errRedirectUrl });
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
    console.log('[RP] JWE envelope detected; decrypting (direct_post.jwt)...');

    let assumedState = state || req.query.sid || req.query.state;

    if (assumedState && transactionStore.has(assumedState)) {
      const tx = transactionStore.get(assumedState);
      if (tx.privateKeyPem) {
        try {
          decryptedPayload = decryptJweResponse(tokenToDecrypt, tx.privateKeyPem);
          state = assumedState;
          console.log(`[RP] JWE decrypted successfully with key belonging to session: ${state}`);
        } catch (err) {
          decryptionError = err;
          console.warn(`[RP] decryption attempt has failed:`, err.message);
        }
      }
    }

    if (!decryptedPayload) {
      console.log('[RP] searching all pending transactions for matching key...');
      for (const [txId, tx] of transactionStore.entries()) {
        if (tx.status === 'PENDING' && tx.privateKeyPem) {
          try {
            decryptedPayload = decryptJweResponse(tokenToDecrypt, tx.privateKeyPem);
            state = txId;
            console.log(`[RP] JWE decrypted with key belonging to session: ${state}`);
            break;
          } catch (err) {
            console.log(`[RP] key from session ${txId} failed; attempting next key`);
          }
        }
      }
    }

    if (decryptedPayload) {
      if (decryptedPayload.error) {
        console.error(`[RP] ❌ wallet transmitted an error in JWE: ${decryptedPayload.error} (${decryptedPayload.error_description || ''})`);
        if (state && transactionStore.has(state)) {
          const tx = transactionStore.get(state);
          tx.status = 'FAILED';
          tx.errors = [`Wallet protocol error (${decryptedPayload.error}): ${decryptedPayload.error_description || 'wallet rejected the request'}`];
          transactionStore.set(state, tx);
        }
        const errRedirectUrl = `${RP_CONFIG.publicUrl}/error.html?sid=${encodeURIComponent(state || '')}&error=${encodeURIComponent(decryptedPayload.error)}&error_description=${encodeURIComponent(decryptedPayload.error_description || 'Wallet rejected the request')}`;
        return res.status(200).json({ redirect_uri: errRedirectUrl });
      }
      vp_token = decryptedPayload.vp_token;
      wia_token = decryptedPayload.wia_token || wia_token;
    } else {
      console.error('[RP] ❌ JWE decryption has failed; no matching session ID found');
      const errRedirectUrl = `${RP_CONFIG.publicUrl}/error.html?error=decryption_failed&error_description=${encodeURIComponent(decryptionError ? decryptionError.message : 'Payload could not be decoded with any active session key')}`;
      return res.status(200).json({ redirect_uri: errRedirectUrl });
    }
  }

  console.log(`[RP] callback session (state): ${state}`);

  if (!state || !transactionStore.has(state)) {
    const errRedirectUrl = `${RP_CONFIG.publicUrl}/error.html?error=invalid_session&error_description=${encodeURIComponent('Transaction context missing or expired')}`;
    return res.status(200).json({ redirect_uri: errRedirectUrl });
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

    console.log(`[RP] starting session validation for session ID: ${state}...`);
    const verificationResult = await verifier.verifyPresentation(parsedVpToken, wia_token);

    if (verificationResult.success) {
      console.log(`[RP] ✅ verification successful; ${verificationResult.format} format processed for session ${state}.`);

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
      console.error(`[RP] ❌ verification has failed:`, verificationResult.errors);
      tx.status = 'FAILED';
      tx.errors = verificationResult.errors;
      transactionStore.set(state, tx);

      const errDesc = verificationResult.errors ? verificationResult.errors.join('; ') : 'Cryptographic verification has failed';
      const errRedirectUrl = `${RP_CONFIG.publicUrl}/error.html?sid=${encodeURIComponent(state)}&error=verification_failed&error_description=${encodeURIComponent(errDesc)}`;
      return res.status(200).json({ redirect_uri: errRedirectUrl });
    }
  } catch (err) {
    console.error('Internal direct_post error:', err);
    if (state && transactionStore.has(state)) {
      const tx = transactionStore.get(state);
      tx.status = 'FAILED';
      tx.errors.push(err.message);
      transactionStore.set(state, tx);
    }
    const errRedirectUrl = `${RP_CONFIG.publicUrl}/error.html?sid=${encodeURIComponent(state || '')}&error=server_error&error_description=${encodeURIComponent(err.message)}`;
    return res.status(200).json({ redirect_uri: errRedirectUrl });
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
// ENDPOINTS FOR ISSUANCE & ATTESTATION VALIDATION (OPENID4VCI)
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
    credential_configuration_ids: ['Employee_ID_SD_JWT_VC'],
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

// route for provisioning logo & visuals for Credential Display Metadata
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
    credential_response_encryption: {
      alg_values_supported: ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"],
      enc_values_supported: ["A128GCM", "A256GCM"],
      encryption_required: false
    },
    credential_request_encryption: {
      alg_values_supported: ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"],
      enc_values_supported: ["A128GCM", "A256GCM"],
      encryption_required: false,
      jwks: {
        keys: [
          {
            ...demoIssuerKeys.publicKey.export({ format: 'jwk' }),
            kid: 'issuer-enc-key-1',
            alg: 'ECDH-ES',
            use: 'enc'
          }
        ]
      }
    },
    credential_configurations_supported: {
      "Employee_ID_SD_JWT_VC": {
        format: "dc+sd-jwt",
        scope: "Employee_ID_SD_JWT_VC",
        credential_signing_alg_values_supported: ["ES256"],
        cryptographic_binding_methods_supported: ["jwk"],
        credential_response_encryption: {
          alg_values_supported: ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"],
          enc_values_supported: ["A128GCM", "A256GCM"],
          encryption_required: false
        },
        credential_request_encryption: {
          alg_values_supported: ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"],
          enc_values_supported: ["A128GCM", "A256GCM"],
          encryption_required: false,
          jwks: {
            keys: [
              {
                ...demoIssuerKeys.publicKey.export({ format: 'jwk' }),
                kid: 'issuer-enc-key-1',
                alg: 'ECDH-ES',
                use: 'enc'
              }
            ]
          }
        },
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
      typ: 'openid-credential-issuer-signed-metadata+jwt'
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

    console.log('[ISS] generated signed_metadata (HAIP)');

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
    console.error('[ISS] error while signing signed_metadata:', e);
    res.json(metadata);
  }
});

app.get([
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
  '/.well-known/oauth-authorization-server/api/issuance',
  '/.well-known/openid-configuration/api/issuance',
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
    dpop_signing_alg_values_supported: ["ES256", "RS256"],
    credential_response_encryption: {
      alg_values_supported: ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"],
      enc_values_supported: ["A128GCM", "A256GCM"],
      encryption_required: false
    },
    credential_request_encryption: {
      alg_values_supported: ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"],
      enc_values_supported: ["A128GCM", "A256GCM"],
      encryption_required: false,
      jwks: {
        keys: [
          {
            ...demoIssuerKeys.publicKey.export({ format: 'jwk' }),
            kid: 'issuer-enc-key-1',
            alg: 'ECDH-ES',
            use: 'enc'
          }
        ]
      }
    },
  });
});

app.post('/api/issuance/nonce', (req, res) => {
  console.log('[ISS] received nonce request');
  const nonces = pidIssuer.generateNonceResponse();
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json(nonces);
});

app.post('/api/issuance/token', (req, res) => {
  console.log('[ISS] received token request');

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
    console.log('[ISS] ✅ token rRequest verified successfully; generating access token...');

    const accessToken = 'access_token_' + crypto.randomBytes(16).toString('hex');
    const nonceResponse = pidIssuer.generateNonceResponse();

    accessTokenStore.set(accessToken, {
      dpopKey: tokenResult.dpopKey,
      scope: 'Employee_ID_SD_JWT_VC',
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
    console.error('[ISS] ❌ token verification has failed:', tokenResult.errors);
    res.status(400).json({
      error: 'invalid_request',
      error_description: tokenResult.errors.join(', ')
    });
  }
});

app.post('/api/issuance/credential', (req, res) => {
  console.log('[ISS] received credential request');

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('DPoP ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'DPoP access token is required in authorization header'
    });
  }
  const accessToken = authHeader.substring(5);
  const tokenData = accessTokenStore.get(accessToken);

  if (!tokenData) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid, unknown or expired access token'
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

    console.log('[ISS] ✅ attestation possession verification successfully; generating EAA (Employee ID Card SD-JWT VC)...');

    const defaultClaims = {
      given_name: 'Max',
      family_name: 'Mustermann',
      employee_id: 'EMP-2026-8942',
      department: 'IT-Infrastruktur & Sicherheit',
      role: 'Senior Security Architect',
      vct: 'urn:company:employee_id:1'
    };

    const finalClaims = tokenData.claims || defaultClaims;
    if (!finalClaims.vct) {
      finalClaims.vct = 'urn:company:employee_id:1';
    }
    const validityDays = tokenData.validityDays || 365;

    const signedEaa = pidIssuer.issuePID({
      claims: finalClaims,
      holderJwk: credResult.devicePublicKeyJwk,
      validityDays: validityDays
    });

    if (tokenData.sid && transactionStore.has(tokenData.sid)) {
      const tx = transactionStore.get(tokenData.sid);
      tx.status = 'SUCCESS';
      transactionStore.set(tokenData.sid, tx);
      console.log(`[ISS] ✅ session ${tokenData.sid} status = SUCCESS`);
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      credentials: [
        {
          credential: signedEaa
        }
      ]
    });
  } else {
    console.error('[ISS] ❌ attestation possession verification has failed:', credResult.errors);
    res.status(400).json({
      error: 'invalid_proof',
      error_description: credResult.errors.join(', ')
    });
  }
});

// launching the API REST server
app.listen(PORT, () => {
  console.log(`=== EUDI WALLET REST API SERVER (PRESENTATION & ISSUANCE) ===`);
  console.log(`Server is running at: http://localhost:${PORT}`);
  if (isRfc9101StrictModeEnabled()) {
    console.log(`[RP] 🔒 RFC 9101 Strict Mode ACTIVE`);
  } else {
    console.log(`[RP] ℹ️ RFC 9101 Strict Mode INACTIVE`);
  }
  console.log(`Public RP identity (client_id): ${RP_CONFIG.clientId}`);
  console.log(`Public issuer identity (issuer_id): ${ISSUER_CONFIG.issuerId}`);
  console.log(`Awaiting incoming wallet requests...`);
});

module.exports = app;