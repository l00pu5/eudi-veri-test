/**
 * EUDI Wallet - Relying Party (RP) Express REST API Server
 * 
 * Dieses Express-Modul implementiert die vollständigen Endpunkte für ein RP-Backend
 * im EUDI-Wallet-Ökosystem gemäß den eIDAS 2.0 (OpenID4VP) Spezifikationen.
 * Es verwendet das zuvor erstellte Validierungsmodul 'eudi-verifier-helper-v2.js'.
 * 
 * Ablaufschritte im Server:
 * 1. GET /api/presentation/initiate     - Startet Session, generiert Nonce/State und liefert den QR-Code-Inhalt (openid4vp://).
 * 2. GET /api/presentation/request-jwt  - Liefert das signierte Request Object (JAR) an die Wallet (request_uri).
 * 3. POST /api/presentation/callback     - direct_post Endpunkt für die Wallet-Response (vp_token, state). Verifiziert die 4 Säulen.
 * 4. GET /api/presentation/status       - Polling-Endpunkt für das Frontend zur Überprüfung des Login-Erfolgs.
 * 
 * Installation der benötigten Pakete:
 * npm install express express-session body-parser cors
 */

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const { EUDIVerifier } = require('./eudi-verifier-helper-v2');
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware konfigurieren
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session-Management zur Speicherung von Nonce und Verifizierungsergebnissen
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 300000 } // 5 Minuten Gültigkeit
}));

// In-Memory Speicher für transienten Status-Abgleich (Alternative zu Redis im Produktivbetrieb)
const transactionStore = new Map();

// Konfiguration der Relying Party
const RP_CONFIG = {
  clientId: 'x509_san_dns:client.example.org',
  publicUrl: 'https://client.example.org', // Die öffentliche URL dieser RP-Schnittstelle
  // Im echten Betrieb laden Sie hier die PEM-Schlüssel aus Ihrem Trust-Store/Trusted List
  trustedIssuerKeys: [], // Befüllt im Initialisierungs-Block unten
  trustedWalletKeys: []
};

// Kryptografische Schlüssel für Demo-Betrieb generieren (simuliert Trust-Store)
let demoIssuerKeys, demoWalletKeys, rpSigningKeys;
try {
  demoIssuerKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  demoWalletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  rpSigningKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); // Zum Signieren des JARs

  RP_CONFIG.trustedIssuerKeys.push(demoIssuerKeys.publicKey.export({ type: 'spki', format: 'pem' }));
  RP_CONFIG.trustedWalletKeys.push(demoWalletKeys.publicKey.export({ type: 'spki', format: 'pem' }));
} catch (e) {
  console.error('Fehler bei der Schlüsselgenerierung:', e);
}

// =============================================================================
// ENDPUNKT 0: index.html präsentieren
// =============================================================================
app.get('/', (req, res) => {
  res.status(200).sendFile(path.join(__dirname, '.', 'index.html'));
});

// =============================================================================
// ENDPUNKT 1: PRÄSENTATION INITIEREIN (QR-Code-Inhalt generieren)
// =============================================================================
app.get('/api/presentation/initiate', (req, res) => {
  // 1. Eindeutige Session-Parameter generieren
  const sessionId = 'session_' + crypto.randomBytes(12).toString('hex');
  const nonce = 'nonce_' + crypto.randomBytes(16).toString('hex');

  // In der HTTP-Session des Nutzers ablegen (Web-Browser)
  req.session.sessionId = sessionId;
  req.session.expectedNonce = nonce;
  req.session.verificationStatus = 'PENDING';

  // Transaktionsdaten im globalen Cache registrieren, damit der asynchrone direct_post Callback darauf zugreifen kann
  transactionStore.set(sessionId, {
    nonce: nonce,
    status: 'PENDING',
    claims: null,
    errors: [],
    responseCode: null
  });

  // 2. request_uri für die Wallet-Abfrage definieren (JAR-Endpunkt)
  const requestUri = `${RP_CONFIG.publicUrl}/api/presentation/request-jwt?sid=${sessionId}`;

  // 3. EUDI-Protokoll-Schema URL für den QR-Code erzeugen (openid4vp://)
  const qrCodeUrl = `openid4vp://?client_id=${encodeURIComponent(RP_CONFIG.clientId)}&request_uri=${encodeURIComponent(requestUri)}`;

  console.log(`[RP Server] Session initiiert. ID: ${sessionId}, Erwartete Nonce: ${nonce}`);

  res.json({
    success: true,
    sessionId: sessionId,
    qrCodeUrl: qrCodeUrl,
    pollEndpoint: `/api/presentation/status?sid=${sessionId}`
  });
});

// =============================================================================
// ENDPUNKT 2: REQUEST OBJECT (JAR) BEREITSTELLEN (Aufruf durch Wallet-App)
// =============================================================================
app.get('/api/presentation/request-jwt', (req, res) => {
  const sessionId = req.query.sid;

  if (!sessionId || !transactionStore.has(sessionId)) {
    return res.status(400).json({ error: 'Ungültige oder abgelaufene Transaktions-ID' });
  }

  const tx = transactionStore.get(sessionId);

  // DCQL Query Definition (Abfrage der Personenidentifikationsdaten / PID)
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

  // Erstellen des unverschlüsselten Request Object Payloads
  const requestPayload = {
    iss: RP_CONFIG.clientId,
    aud: "https://self-issued.me/v2",
    response_type: "vp_token",
    response_mode: "direct_post",
    response_uri: `${RP_CONFIG.publicUrl}/api/presentation/callback`,
    client_id: RP_CONFIG.clientId,
    nonce: tx.nonce,
    state: sessionId, // state wird als Session-Koppler an Callback zurückgegeben
    dcql_query: dcqlQuery
  };

  // JAR-JWT Header deklarieren
  const jwtHeader = {
    alg: 'ES256',
    typ: 'oauth-authz-req+jwt'
  };

  // Signieren des JAR (Kryptografische Absicherung des Requests vor Taint-Angriffen)
  try {
    const tokenInput = `${Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(requestPayload)).toString('base64url')}`;
    const signer = crypto.createSign('SHA256');
    signer.update(tokenInput);
    const signature = signer.sign(rpSigningKeys.privateKey, 'base64url');
    const signedJwt = `${tokenInput}.${signature}`;

    console.log(`[RP Server] JAR-Request für Session ${sessionId} an Wallet ausgeliefert.`);

    // Rückgabe mit dem gesetzlich vorgeschriebenen Media-Type für JAR
    res.setHeader('Content-Type', 'application/oauth-authz-req+jwt');
    res.setHeader('Cache-Control', 'no-store');
    res.send(signedJwt);
  } catch (err) {
    console.error('JAR Signierungsfehler:', err);
    res.status(500).json({ error: 'Kryptografischer Serverfehler beim Erzeugen des JAR' });
  }
});

// =============================================================================
// ENDPUNKT 3: DIRECT_POST CALLBACK (Asynchroner Empfang des vp_tokens von Wallet)
// =============================================================================
app.post('/api/presentation/callback', async (req, res) => {
  // direct_post liefert Parameter als application/x-www-form-urlencoded
  const { vp_token, state, wia_token } = req.body;

  console.log(`[RP Server] direct_post Callback erhalten. State (Session-ID): ${state}`);

  if (!state || !transactionStore.has(state)) {
    return res.status(400).json({ error: 'Transaktions-Kontext fehlt oder abgelaufen' });
  }

  const tx = transactionStore.get(state);

  try {
    // Parser des vp_tokens aus dem String- oder JSON-Format
    let parsedVpToken;
    try {
      parsedVpToken = JSON.parse(vp_token);
    } catch (e) {
      // Falls es als URL-codierter JSON-String kam, parsen
      parsedVpToken = JSON.parse(decodeURIComponent(vp_token));
    }

    // Instanziierung des EUDIVerifiers mit der in Schritt 1 festgelegten Nonce
    const verifier = new EUDIVerifier({
      clientId: RP_CONFIG.clientId,
      expectedNonce: tx.nonce,
      trustedIssuerKeys: RP_CONFIG.trustedIssuerKeys,
      trustedWalletKeys: RP_CONFIG.trustedWalletKeys
    });

    // 4-Säulen-Prüfung ausführen
    console.log(`[RP Server] Starte 4-Säulen-Validierung für Session: ${state}...`);
    const verificationResult = await verifier.verifyPresentation(parsedVpToken, wia_token);

    if (verificationResult.success) {
      console.log(`[RP Server] ✅ Verifizierung erfolgreich! Claims für ${state} extrahiert.`);

      // Einmaligen transienten Response Code für sichere Browser-Kopplung generieren (Session Fixation Schutz)
      const responseCode = crypto.randomBytes(16).toString('hex');

      // Status im globalen Cache updaten
      tx.status = 'SUCCESS';
      tx.claims = verificationResult.claims;
      tx.responseCode = responseCode;
      transactionStore.set(state, tx);

      // Erfolgs-Response an die Wallet gemäß direct_post Spezifikation
      // Wir leiten die Wallet zur Browser-Zielseite weiter, die den Response Code einlöst
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

// =============================================================================
// ENDPUNKT 4: STATUS POLLING FÜR FRONTEND (Browser)
// =============================================================================
app.get('/api/presentation/status', (req, res) => {
  const sessionId = req.query.sid;

  if (!sessionId || !transactionStore.has(sessionId)) {
    return res.status(404).json({ success: false, status: 'NOT_FOUND', error: 'Ungültige Sitzung' });
  }

  const tx = transactionStore.get(sessionId);

  // Browser fragt Status ab
  if (tx.status === 'SUCCESS') {
    // Falls der Browser anfragt, prüfen wir, ob die lokale HTTP-Session des Browsers mit dem Status übereinstimmt
    // Im echten Szenario löst der Browser-Redirect den 'response_code' ein. Hier liefern wir ihn zur vereinfachten Demo direkt:
    return res.json({
      success: true,
      status: 'SUCCESS',
      claims: tx.claims, // Verifizierte Identitätsdaten (z. B. Erika Mustermann)
      responseCode: tx.responseCode
    });
  } else if (tx.status === 'FAILED') {
    return res.json({
      success: false,
      status: 'FAILED',
      errors: tx.errors
    });
  }

  // Standardmäßig noch am Scannen / Warten
  res.json({
    success: true,
    status: 'PENDING'
  });
});

// Starten des API-Servers
app.listen(PORT, () => {
  console.log(`\n=== EUDI WALLET relying PARTY EXPRESS SERVER ===`);
  console.log(`Server läuft lokal auf: http://localhost:${PORT}`);
  console.log(`Öffentliche RP-Identität (client_id): ${RP_CONFIG.clientId}`);
  console.log(`Warte auf Wallet-Verbindungen...\n`);
});

module.exports = app;
